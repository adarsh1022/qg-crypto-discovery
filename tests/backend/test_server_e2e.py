"""The whole product over real sockets: a real uvicorn server, the real agent, the real scanner, a temporary certificate
directory and a temporary database. Nothing is mocked."""
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

import pfxgen
from agent.client import BackendClient
from agent.runner import poll_once
from agentfx import options
from backend.app import create_app
from backend.settings import Settings
from test_api_e2e import INTER, LEAF, ROOT_CERT, build_tree
from treegen import run_scan

uvicorn = pytest.importorskip("uvicorn")
REPO = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(url: str, seconds: float = 20.0) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.1)
    raise AssertionError(f"{url} did not come up")


class ThreadServer:
    def __init__(self, db_path, port):
        app = create_app(Settings(db_path=db_path, sweep_interval_s=None))
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, access_log=False, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=15)


def check_results(base, run_id, tree):
    records, summary = run_scan(str(tree))
    run = httpx.get(f"{base}/api/runs/{run_id}").json()["run"]
    assert run["status"] == "completed" and run["record_count"] == len(records) == 8
    assert run["finding_count"] == 6 and run["error_count"] == 0 and run["agent_summary"]["records"] == 8
    summary_view = httpx.get(f"{base}/api/runs/{run_id}/fs/summary").json()
    assert summary_view["run"]["run_id"] == run_id
    totals = summary_view["totals"]
    assert (totals["records"], totals["sightings"], totals["unique_certificates"]) == (8, 6, 3)
    certs = httpx.get(f"{base}/api/runs/{run_id}/fs/certificates").json()["items"]
    assert {c["sha256"] for c in certs} == {pfxgen.fp(d) for d in (LEAF, INTER, ROOT_CERT)}
    observations = httpx.get(f"{base}/api/runs/{run_id}/fs/observations").json()
    assert observations["total"] == 8                                  # 6 sightings + 2 key-only files
    dashboard = httpx.get(f"{base}/api/dashboard")
    assert dashboard.status_code == 200
    return run


def test_real_server_real_agent_real_scan(tmp_path):
    tree = build_tree(tmp_path / "certs")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with ThreadServer(tmp_path / "e2e.db", port):
        wait_for(f"{base}/api/meta")
        created = httpx.post(f"{base}/api/runs", json={"type": "filesystem", "config": {"roots": [str(tree)]}})
        assert created.status_code == 201
        run_id = created.json()["run"]["run_id"]
        report = poll_once(BackendClient(base), options(batch_size=3))
        assert (report.outcome, report.final_status, report.batches) == ("finished", "completed", 3)
        check_results(base, run_id, tree)
    assert (tmp_path / "e2e.db").is_file()


def test_real_server_cancellation_over_http(tmp_path):
    tree = build_tree(tmp_path / "certs")
    for i in range(30):
        (tmp_path / "certs" / "more").mkdir(exist_ok=True)
        (tmp_path / "certs" / "more" / f"f{i}.txt").write_bytes(b"x")
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with ThreadServer(tmp_path / "cancel.db", port):
        wait_for(f"{base}/api/meta")
        run_id = httpx.post(f"{base}/api/runs", json={"type": "filesystem", "config": {"roots": [str(tree)]}}).json()["run"]["run_id"]
        client = BackendClient(base)
        original_upload = client.upload
        uploads = []

        def cancel_after_first(run, token, items):
            answer = original_upload(run, token, items)
            if not uploads:
                assert httpx.post(f"{base}/api/runs/{run}/cancel").status_code == 200
            uploads.append(1)
            return answer

        client.upload = cancel_after_first
        report = poll_once(client, options(batch_size=1))
        assert report.cancelled and report.final_status == "partial"
        assert httpx.get(f"{base}/api/runs/{run_id}").json()["run"]["status"] == "partial"


def test_python_m_backend_and_python_m_agent_as_separate_processes(tmp_path):
    tree = build_tree(tmp_path / "certs")
    db = tmp_path / "data" / "agent.db"                                  # the parent folder does not exist yet
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONIOENCODING": "utf-8"}
    out = tmp_path / "backend.out"
    with open(out, "wb") as sink:
        server = subprocess.Popen([sys.executable, "-m", "backend", "--db", str(db), "--port", str(port)],
                                  cwd=REPO, env=env, stdout=sink, stderr=subprocess.STDOUT)
        try:
            wait_for(f"{base}/api/meta")
            run_id = httpx.post(f"{base}/api/runs", json={"type": "filesystem", "config": {"roots": [str(tree)]}}).json()["run"]["run_id"]
            agent = subprocess.run([sys.executable, "-m", "agent", "--server", base, "--once", "--batch-size", "4"],
                                   cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
            assert agent.returncode == 0, (agent.stdout, agent.stderr)
            assert f"run {run_id}: finished" in agent.stdout and "8 records" in agent.stdout
            check_results(base, run_id, tree)
            nothing = subprocess.run([sys.executable, "-m", "agent", "--server", base, "--once"],
                                     cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
            assert nothing.returncode == 0 and "no queued filesystem run" in nothing.stdout
            # the lease token and certificate content never reach the agent's output either
            assert "BEGIN" not in agent.stdout + agent.stderr and str(tree) not in agent.stdout + agent.stderr
        finally:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
    assert db.is_file()
    text = out.read_text(encoding="utf-8", errors="replace")
    assert f"127.0.0.1:{port}" in text and str(db) in text               # the startup line
    assert "GET /api" not in text and "POST /api" not in text            # no per-request access log


def test_the_backend_listens_on_loopback_only(tmp_path):
    port = free_port()
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    server = subprocess.Popen([sys.executable, "-m", "backend", "--db", str(tmp_path / "x.db"), "--port", str(port)],
                              cwd=REPO, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        wait_for(f"http://127.0.0.1:{port}/api/meta")
        others = {a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)} - {"127.0.0.1"}
        for address in others:
            with socket.socket() as s:
                s.settimeout(2)
                assert s.connect_ex((address, port)) != 0, f"reachable on {address}"
    finally:
        server.terminate()
        server.wait(timeout=20)


@pytest.mark.parametrize("args", [["--port", "0"], ["--port", "70000"], ["--host", "0.0.0.0"], ["--data-origin", "bogus"]])
def test_backend_rejects_bad_arguments(args):
    result = subprocess.run([sys.executable, "-m", "backend", *args], cwd=REPO, capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2


@pytest.mark.parametrize("args", [["--server", "http://example.com:8765"], ["--server", "https://127.0.0.1:8765"],
                                  ["--poll-interval", "0"], ["--poll-interval", "1000"], ["--batch-size", "501"],
                                  ["--agent-id", "bad id!"]])
def test_agent_rejects_bad_arguments(args):
    result = subprocess.run([sys.executable, "-m", "agent", "--once", *args], cwd=REPO, capture_output=True, text=True, timeout=60,
                            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 2


def test_agent_once_reports_an_unreachable_backend():
    port = free_port()
    result = subprocess.run([sys.executable, "-m", "agent", "--once", "--server", f"http://127.0.0.1:{port}"], cwd=REPO,
                            capture_output=True, text=True, timeout=60, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    assert result.returncode == 3 and "not reachable" in result.stderr
