"""The packaged agent, end to end: a real backend process, a queued filesystem run, and `python qg-agent.pyz --once` finishing it, with
the same results as `python -m agent`. Everything is on loopback with temporary folders and a temporary database."""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import build_agent_pyz  # noqa: E402
import make_demo_certs  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise AssertionError(f"{url} did not come up")


def queue(base, folder):
    reply = httpx.post(f"{base}/api/runs", json={"type": "filesystem", "config": {"roots": [str(folder)]}})
    assert reply.status_code == 201, reply.text
    return reply.json()["run"]["run_id"]


def test_the_packaged_agent_completes_a_run_with_the_same_results_as_python_m_agent(tmp_path):
    demo = tmp_path / "demo"
    make_demo_certs.create(demo)
    pyz = tmp_path / "qg-agent.pyz"
    assert build_agent_pyz.main(["--output", str(pyz)]) == 0

    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    with open(tmp_path / "backend.out", "wb") as sink:
        server = subprocess.Popen([sys.executable, "-m", "backend", "--db", str(tmp_path / "db" / "agent.db"), "--port", str(port)],
                                  cwd=REPO, env=env, stdout=sink, stderr=subprocess.STDOUT)
        try:
            wait_for(f"{base}/api/meta")
            first, second = queue(base, demo), queue(base, demo)
            elsewhere = tmp_path / "elsewhere"                                        # not the repository: the archive must stand alone
            elsewhere.mkdir()
            packaged = subprocess.run([sys.executable, str(pyz), "--server", base, "--once", "--agent-id", "pyz-agent"], cwd=elsewhere, env=env, capture_output=True, text=True, timeout=120)
            assert packaged.returncode == 0, (packaged.stdout, packaged.stderr)
            assert f"run {first}: finished" in packaged.stdout and "7 records" in packaged.stdout
            module = subprocess.run([sys.executable, "-m", "agent", "--server", base, "--once", "--agent-id", "module-agent"], cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
            assert module.returncode == 0, (module.stdout, module.stderr)

            runs = {rid: httpx.get(f"{base}/api/runs/{rid}").json()["run"] for rid in (first, second)}
            assert {r["status"] for r in runs.values()} == {"completed"}
            assert runs[first]["host_id"] == "pyz-agent" and runs[second]["host_id"] == "module-agent"
            assert (runs[first]["record_count"], runs[first]["finding_count"]) == (runs[second]["record_count"], runs[second]["finding_count"]) == (7, 7)
            summaries = [httpx.get(f"{base}/api/runs/{rid}/fs/summary").json() for rid in (first, second)]
            for key in ("totals", "validity", "algorithms", "signature_algorithms"):
                assert summaries[0][key] == summaries[1][key], key
            certificates = [sorted(c["sha256"] for c in httpx.get(f"{base}/api/runs/{rid}/fs/certificates", params={"limit": 100}).json()["items"]) for rid in (first, second)]
            assert certificates[0] == certificates[1] and len(certificates[0]) == 6
            assert "BEGIN" not in packaged.stdout + packaged.stderr and str(demo) not in packaged.stdout + packaged.stderr
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
