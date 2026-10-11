"""tools/make_demo_certs.py: synthetic, certificate-only demo files that the agent's own scanner can read."""
import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tests" / "agent"))
spec = importlib.util.spec_from_file_location("make_demo_certs", REPO / "tools" / "make_demo_certs.py")
make_demo_certs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make_demo_certs)

from treegen import run_scan  # noqa: E402  (the repository's own scan helper)


def test_it_writes_certificate_files_and_never_a_private_key(tmp_path):
    done = subprocess.run([sys.executable, str(REPO / "tools" / "make_demo_certs.py"), "--out", str(tmp_path / "demo")], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    files = sorted((tmp_path / "demo").iterdir())
    assert [f.name for f in files] == sorted(["valid-rsa2048.pem", "valid-ec-p256.pem", "strong-rsa3072.pem", "valid-ec-p384.pem", "expiring-soon.pem", "expired.pem", "copy-of-valid-rsa2048.pem"])
    for path in files:
        text = path.read_text()
        assert text.startswith("-----BEGIN CERTIFICATE-----") and "PRIVATE" not in text and "KEY-----" not in text
    assert "no private keys" in done.stdout


def test_the_agents_own_scanner_finds_the_variety_the_demo_needs(tmp_path):
    make_demo_certs.create(tmp_path / "demo")
    records, summary = run_scan(tmp_path / "demo", now=__import__("datetime").datetime.now(__import__("datetime").timezone.utc))
    found = [r for r in records if r["parse_status"] == "ok"]
    assert len(found) == 7 and len({r["sha256"] for r in found}) == 6                      # one certificate is stored twice
    assert {r["validity_status"] for r in found} == {"valid", "expiring", "expired"}
    assert {(r["key_algorithm"], r["key_size"], r["key_curve"]) for r in found} >= {("RSA", 2048, None), ("RSA", 3072, None)}
    assert {r["signature_algorithm"] for r in found} == {"sha256WithRSAEncryption", "ecdsa-with-SHA256", "sha384WithRSAEncryption", "ecdsa-with-SHA384"}
    assert all(not r["subject"] or r["subject"].endswith(".demo.local") for r in found)
