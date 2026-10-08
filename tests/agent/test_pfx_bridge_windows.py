"""agent.pfx_bridge against REAL Windows PowerShell and real PKCS#12 files.

Nothing about the OS is mocked here. Fixtures come from three independent producers: `cryptography`,
.NET's own exporter (the realistic Windows flavour: empty password, certificates in an encryptedData
container, key shrouded in a separate container) and hand-built structures. A wrapper records what
actually crosses the process boundary while still making the real call.
"""
import base64
import json
import os
import subprocess

import pytest

import pfxgen
from agent import pfx_bridge
from agent.pfx_bridge import read_pkcs12
from pfxgen import fp
from test_fs_scan_safety import audited

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell bridge")

ROOT, INTER, LEAF = pfxgen.chain()


def native(mode):
    try:
        return pfxgen.windows_native(mode)
    except pfxgen.FixtureUnavailable as e:
        pytest.skip(f"cannot create a Windows-native fixture here: {e}")


@pytest.fixture
def recorded(monkeypatch):
    """Make the REAL call, but remember exactly what was sent to PowerShell."""
    calls = []
    real = pfx_bridge._run_powershell

    def wrapper(payload_b64, timeout):
        done = real(payload_b64, timeout)
        calls.append({"payload": base64.b64decode(payload_b64), "timeout": timeout, "stdout": done.stdout,
                      "stderr": done.stderr, "returncode": done.returncode})
        return done
    monkeypatch.setattr(pfx_bridge, "_run_powershell", wrapper)
    return calls


def fps(result):
    return sorted(e.cert.sha256 for e in result.entries if e.cert)


# ================================================================ happy paths with a real OS
def test_windows_exported_pfx_with_a_private_key_returns_all_public_certificates(recorded):
    pfx = native("chain")
    assert pfxgen.container_types(pfx) == ["1.2.840.113549.1.7.1", "1.2.840.113549.1.7.6"]     # key | certs
    result = read_pkcs12(pfx, max_certs=100)
    assert (result.format, result.file_status, result.detail) == ("pkcs12", "ok", None)
    assert fps(result) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert len(recorded) == 1 and recorded[0]["returncode"] == 0


def test_certificate_only_pfx_without_any_key(recorded):
    result = read_pkcs12(native("certs_only"), max_certs=100)
    assert result.file_status == "ok" and fps(result) == sorted([fp(INTER), fp(ROOT)])


def test_single_certificate_pfx_keeps_the_json_array_shape(recorded):
    result = read_pkcs12(native("single"), max_certs=100)
    assert result.file_status == "ok" and fps(result) == [fp(INTER)]
    assert json.loads(recorded[0]["stdout"])["certs"] == [base64.b64encode(INTER).decode()]


def test_plain_cryptography_pfx_needs_no_process(recorded):
    result = read_pkcs12(pfxgen.plain_with_key(), max_certs=100)
    assert result.file_status == "ok" and len(result.entries) == 3 and recorded == []


def test_duplicate_certificates_survive_a_real_round_trip(recorded):
    result = read_pkcs12(native("duplicate"), max_certs=100)          # Inter, Inter, Root through the real OS
    assert result.file_status == "ok" and result.total_certificates == 3
    assert fps(result) == sorted([fp(INTER), fp(INTER), fp(ROOT)])    # nothing silently discarded
    assert result.entries[0].cert.sha256 in {e.cert.sha256 for e in result.entries[1:]}


def test_max_certs_is_enforced_with_a_real_os(recorded):
    result = read_pkcs12(native("chain"), max_certs=2)
    assert len(result.entries) == 2 and result.truncated and result.detail == "bundle_truncated"


# ================================================================ nothing is guessed
@pytest.mark.parametrize("maker", [lambda: pfxgen.protected(), lambda: pfxgen.protected(legacy=True),
                                   lambda: native("protected")], ids=["cryptography_aes", "cryptography_3des", "windows_native"])
def test_password_protected_pfx_is_reported_not_guessed(recorded, maker):
    pfx = maker()
    result = read_pkcs12(pfx, max_certs=100)
    assert (result.file_status, result.detail, result.entries) == ("unsupported", "pkcs12_password_protected", ())
    assert len(recorded) == 1                                # one attempt, no retries, no password variants
    assert b"secret" not in recorded[0]["payload"] and b"secret" not in recorded[0]["stdout"]


def test_corruption_inside_the_encrypted_container_is_never_reported_with_full_confidence(recorded):
    """The key-free payload has no MAC, so the OS cannot detect corruption: some single-byte corruptions
    decrypt to altered-but-parseable certificates. Whatever comes back through the OS must say so."""
    from agent.observations import records_from_file_parse
    import datetime as dt
    pfx = native("chain")
    original = {fp(ROOT), fp(INTER), fp(LEAF)}
    container = pfxgen.containers_of(pfx)[-1]
    start = pfx.find(container)
    seen = set()
    for pos in range(start + len(container) - 1100, start + len(container) - 10, 97):
        mutated = bytearray(pfx)
        mutated[pos] ^= 0xFF
        result = read_pkcs12(bytes(mutated), max_certs=100)
        seen.add((result.file_status, result.detail))
        assert result.file_status in ("ok", "partial", "unsupported", "no_certificate", "malformed")
        for rec in records_from_file_parse("p", "f.pfx", "r", result, dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc), 30):
            if rec["parse_status"] == "ok":
                assert pfx_bridge.INTEGRITY_WARNING in rec["warnings"]          # every OS-decrypted certificate
                assert rec["evidence_confidence"] == "medium"                   # is capped, even if it looks fine
                assert rec["chain_index"] is None
    assert ("unsupported", "pkcs12_password_protected") in seen or any(s[0] == "ok" for s in seen)


def test_structurally_corrupt_pfx_never_reaches_the_os(recorded):
    pfx = native("chain")
    assert read_pkcs12(pfx[:len(pfx) // 2], max_certs=100).detail == "pkcs12_malformed"
    assert read_pkcs12(bytes(range(256)) * 4, max_certs=100).detail == "pkcs12_malformed"
    assert recorded == []


# ================================================================ PowerShell never receives a key container
@pytest.mark.parametrize("maker", [lambda: native("chain"), lambda: pfxgen.protected(), lambda: pfxgen.protected(legacy=True)],
                         ids=["windows_native", "cryptography_aes", "cryptography_3des"])
def test_real_payload_contains_no_key_container(recorded, maker):
    pfx = maker()
    secrets = pfxgen.shrouded_key_values(pfx)
    assert secrets and all(len(s) > 200 for s in secrets), "fixture must contain a key container"
    read_pkcs12(pfx, max_certs=100)
    payload = recorded[0]["payload"]
    assert set(pfxgen.container_types(payload)) == {"1.2.840.113549.1.7.6"}      # only encryptedData
    assert not pfxgen.has_mac(payload)
    original = pfxgen.containers_of(pfx)
    forwarded = pfxgen.containers_of(payload)
    assert forwarded and all(f in original for f in forwarded)                   # byte-identical copies, nothing invented
    for value in secrets:
        assert value not in payload
        for i in range(0, len(value) - 40):
            assert value[i:i + 40] not in payload, "key bag bytes reached PowerShell"


def test_nothing_from_the_key_appears_in_the_output_or_the_process_streams(recorded, capsys, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    pfx = native("chain")
    result = read_pkcs12(pfx, max_certs=100)
    text = json.dumps(result.to_dict()) + repr(result)
    streams = recorded[0]["stdout"] + recorded[0]["stderr"]
    for value in pfxgen.shrouded_key_values(pfx):
        for hexed in (value.hex(), base64.b64encode(value).decode()):
            for i in range(0, len(hexed) - 32, 5):
                assert hexed[i:i + 32] not in text
                assert hexed[i:i + 32].encode() not in streams
        assert value not in streams
    out = capsys.readouterr()
    assert out.out == "" and out.err == "" and caplog.text == ""


# ================================================================ process arguments, temp files, environment
def test_real_process_is_started_once_with_constant_arguments(monkeypatch):
    pfx = native("chain")
    marker = base64.b64encode(pfxgen.containers_of(pfx)[-1])[:60]
    with audited() as events:
        result = read_pkcs12(pfx, max_certs=100)
    assert result.file_status == "ok"
    popen = [args for name, args in events if name == "subprocess.Popen"]
    assert len(popen) == 1
    _executable, argv, _cwd, _env = popen[0]            # on Windows Popen reports the command line as one string
    command = argv if isinstance(argv, str) else subprocess.list2cmdline(list(argv))
    exe = os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    assert command == subprocess.list2cmdline([exe, "-NoLogo", "-NoProfile", "-NonInteractive",
                                               "-EncodedCommand", pfx_bridge._ENCODED_SCRIPT])
    assert marker.decode() not in command and len(command) < 3000        # constant script only, no file data
    assert not [e for e in events if e[0] not in ("subprocess.Popen", "open")]            # nothing else happened


def test_no_temporary_files_are_created_or_left_behind(tmp_path, monkeypatch):
    isolated = tmp_path / "tmp"
    isolated.mkdir()
    for var in ("TEMP", "TMP"):
        monkeypatch.setenv(var, str(isolated))
    pfx = native("chain")
    with audited() as events:
        ok = read_pkcs12(pfx, max_certs=100)
        failed = read_pkcs12(pfxgen.protected(), max_certs=100)               # a failing run must clean up too
    assert ok.file_status == "ok" and failed.detail == "pkcs12_password_protected"
    assert list(isolated.iterdir()) == [], "the bridge or PowerShell left temporary files behind"
    for name, (path, mode, flags) in [e for e in events if e[0] == "open"]:
        if isinstance(path, int):
            continue                      # an integer is a pipe descriptor (the child's stdin/stdout), not a file
        assert not (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)), (path, mode)
    assert sorted(os.listdir(tmp_path)) == ["tmp"]


def test_the_child_environment_carries_no_secrets(monkeypatch):
    seen = {}
    real_run = subprocess.run

    def spy(argv, **kwargs):
        seen["env"] = dict(kwargs["env"])
        return real_run(argv, **kwargs)
    monkeypatch.setattr(pfx_bridge.subprocess, "run", spy)
    monkeypatch.setenv("QG_TEST_SECRET_PASSWORD", "hunter2")
    assert read_pkcs12(native("chain"), max_certs=100).file_status == "ok"
    assert "QG_TEST_SECRET_PASSWORD" not in seen["env"] and "hunter2" not in repr(seen["env"])
    assert os.path.join(os.environ["SystemRoot"], "System32") == seen["env"]["PATH"]


# ================================================================ timeout and orphans
def _bridge_processes():
    """Count powershell.exe processes running OUR constant script (excluding the checker itself)."""
    prefix = pfx_bridge._ENCODED_SCRIPT[:48]
    command = ("(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object "
               "{ $_.ProcessId -ne $PID -and $_.CommandLine -like '*" + prefix + "*' } | Measure-Object).Count")
    done = subprocess.run([pfx_bridge._powershell_path(), "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, timeout=60)
    return int(done.stdout.strip() or b"-1")


def test_the_timeout_is_really_enforced_and_leaves_no_process(recorded):
    payload = base64.b64encode(pfx_bridge.build_keyfree_pfx((pfxgen.containers_of(native("chain"))[-1],)))
    import time
    start = time.perf_counter()
    with pytest.raises(subprocess.TimeoutExpired):
        pfx_bridge._run_powershell(payload, 0.05)
    assert time.perf_counter() - start < 5
    time.sleep(0.3)
    assert _bridge_processes() == 0, "a timed-out PowerShell process was left running"


def test_a_timeout_through_the_public_api_is_reported_without_a_retry(monkeypatch):
    real = pfx_bridge._run_powershell
    calls = []

    def short(payload_b64, timeout):
        calls.append(timeout)
        return real(payload_b64, 0.05)
    monkeypatch.setattr(pfx_bridge, "_run_powershell", short)
    result = read_pkcs12(native("chain"), max_certs=100)
    assert (result.file_status, result.detail) == ("read_error", "powershell_timeout") and calls == [30]


def test_no_orphans_after_normal_runs(recorded):
    read_pkcs12(native("chain"), max_certs=100)
    read_pkcs12(pfxgen.protected(), max_certs=100)
    assert _bridge_processes() == 0


# ================================================================ the real output protocol
def test_real_powershell_output_follows_the_strict_protocol(recorded):
    pfx = native("chain")
    read_pkcs12(pfx, max_certs=100)
    kind, ders = pfx_bridge._parse_output(recorded[0]["stdout"])
    assert kind == "ok" and sorted(fp(d) for d in ders) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert recorded[0]["stderr"] == b"" and recorded[0]["stdout"].count(b"\n") <= 1
    read_pkcs12(pfxgen.protected(), max_certs=100)
    assert pfx_bridge._parse_output(recorded[1]["stdout"]) == ("error", "0x80090020")
    assert recorded[1]["returncode"] == 3


def test_real_results_are_strict_utf8_json(recorded):
    result = read_pkcs12(native("chain"), max_certs=100)
    blob = json.dumps(result.to_dict(), ensure_ascii=False).encode("utf-8")
    assert json.loads(blob)["total_certificates"] == 3


# ================================================================ integrity-warning provenance with the real OS
def _mixed_pfx():
    """One real file: INTER as a plain certBag AND a genuine OS-encrypted certificate container (leaf, inter, root)."""
    os_container = pfxgen.containers_of(native("chain"))[-1]
    plain_container = pfxgen.data_container([pfxgen.cert_bag(INTER)])
    return pfxgen.structural_pfx([plain_container, os_container]), os_container, plain_container


def test_real_mixed_file_flags_only_certificates_that_came_through_the_os(recorded):
    import datetime as dt
    from agent.observations import records_from_file_parse
    pfx, os_container, plain_container = _mixed_pfx()
    result = read_pkcs12(pfx, max_certs=100)
    assert result.file_status == "ok" and len(result.entries) == 4

    plain, *from_os = result.entries
    assert plain.cert.sha256 == fp(INTER) and plain.cert.warnings == ()               # direct read: not flagged
    assert sorted(e.cert.sha256 for e in from_os) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert all(e.cert.warnings == (pfx_bridge.INTEGRITY_WARNING,) for e in from_os)   # includes INTER again: flagged here
    assert all(e.parse_status == "ok" for e in result.entries)                        # never rejected for it

    stamp = dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc)
    records = records_from_file_parse("p", "mixed.pfx", "r", result, stamp, 30)
    assert [r["evidence_confidence"] for r in records] == ["high", "medium", "medium", "medium"]
    assert [pfx_bridge.INTEGRITY_WARNING in r["warnings"] for r in records] == [False, True, True, True]

    # and exactly the encrypted container, nothing else, crossed the process boundary
    assert pfxgen.containers_of(recorded[0]["payload"]) == [os_container]
    assert plain_container not in recorded[0]["payload"]


def test_real_native_file_every_certificate_is_flagged_and_capped(recorded):
    import datetime as dt
    from agent.observations import records_from_file_parse
    result = read_pkcs12(native("chain"), max_certs=100)
    records = records_from_file_parse("p", "n.pfx", "r", result, dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc), 30)
    assert len(records) == 3
    assert all(pfx_bridge.INTEGRITY_WARNING in r["warnings"] and r["evidence_confidence"] == "medium" for r in records)
    assert all(r["parse_status"] == "ok" for r in records)
