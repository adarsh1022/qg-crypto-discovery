"""agent.pfx_bridge: structure walk, key withholding, payload, status mapping, output validation.

Everything here runs with NO real PowerShell: the process boundary (`_run_powershell`) is replaced by a
spy, and nothing else is mocked, so the structure walk, the key-free payload and the JSON validation all
run for real. The real end-to-end tests are in test_pfx_bridge_windows.py.
"""
import base64
import json
import os
import random
import subprocess

import pytest

import pfxgen
from agent import pfx_bridge
from agent.der import Tlv
from agent.pfx_bridge import MAX_CONTAINERS, build_keyfree_pfx, read_pkcs12
from pfxgen import (OID_ENVELOPED_DATA, OID_PBES2, OID_SECRET_BAG, OID_SIGNED_DATA, OID_UNKNOWN, cert_bag,
                    container_types, containers_of, data_container, encrypted_container, fp, key_bag, other_bag,
                    structural_pfx)

ROOT, INTER, LEAF = pfxgen.chain()
CANARY = bytes((i * 37 + 11) % 251 for i in range(96))          # recognisable, and NOT valid DER
CANARY2 = bytes((i * 53 + 7) % 251 for i in range(80))


def fps(result):
    return [e.cert.sha256 if e.cert else None for e in result.entries]


def completed(stdout=b"", rc=0, stderr=b""):
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def ok_output(ders):
    return json.dumps({"status": "ok", "certs": [base64.b64encode(d).decode() for d in ders]}).encode()


def error_output(hresult):
    return json.dumps({"status": "error", "hresult": hresult}).encode()


class PowerShellSpy:
    """Replaces ONLY the process boundary. Records exactly what would have been sent to PowerShell."""

    def __init__(self):
        self.calls = []
        self.result = completed(ok_output([]))
        self.raises = None

    def __call__(self, payload_b64, timeout):
        self.calls.append({"payload_b64": payload_b64, "payload": base64.b64decode(payload_b64), "timeout": timeout})
        if self.raises is not None:
            raise self.raises
        return self.result

    def answer(self, ders=(), **kw):
        self.result = completed(ok_output(list(ders)), **kw)


@pytest.fixture
def ps(monkeypatch):
    spy = PowerShellSpy()
    monkeypatch.setattr(pfx_bridge, "_run_powershell", spy)
    monkeypatch.setattr(pfx_bridge, "_is_windows", lambda: True)
    monkeypatch.setattr(pfx_bridge, "_powershell_path", lambda: "C:\\fake\\powershell.exe")
    return spy


def encrypted_pfx(*extra_containers, plain_certs=(), key=True):
    containers = []
    if key:
        containers.append(data_container([key_bag(CANARY)]))
    if plain_certs:
        containers.append(data_container([cert_bag(d) for d in plain_certs]))
    containers.append(encrypted_container())
    containers.extend(extra_containers)
    return structural_pfx(containers)


# ================================================================ plain containers: no process at all
def test_plain_pfx_with_a_private_key_yields_only_public_certificates(ps):
    result = read_pkcs12(pfxgen.plain_with_key(), max_certs=10)
    assert (result.format, result.file_status, result.detail, result.truncated) == ("pkcs12", "ok", None, False)
    assert sorted(fps(result)) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert all(e.parse_status == "ok" for e in result.entries) and result.total_certificates == 3
    assert ps.calls == [], "a plain-container PFX needs no OS call"


def test_plain_certificate_only_pfx(ps):
    result = read_pkcs12(pfxgen.plain_certs_only((LEAF, INTER)), max_certs=10)
    assert sorted(fps(result)) == sorted([fp(LEAF), fp(INTER)]) and ps.calls == []


def test_plain_containers_work_on_any_platform(ps, monkeypatch):
    monkeypatch.setattr(pfx_bridge, "_is_windows", lambda: False)
    result = read_pkcs12(pfxgen.plain_with_key(), max_certs=10)
    assert result.file_status == "ok" and len(result.entries) == 3 and ps.calls == []


def test_duplicate_certificates_inside_one_pfx_are_all_reported(ps):
    result = read_pkcs12(pfxgen.plain_with_key(extra_ca=(LEAF, INTER)), max_certs=10)
    assert sorted(fps(result)) == sorted([fp(LEAF), fp(LEAF), fp(INTER)])      # nothing silently discarded
    assert result.total_certificates == 3 and result.file_status == "ok"


def test_max_certs_is_respected_for_plain_containers(ps):
    pfx = pfxgen.plain_certs_only((ROOT, INTER, LEAF))
    cut = read_pkcs12(pfx, max_certs=2)
    assert len(cut.entries) == 2 and cut.truncated and cut.detail == "bundle_truncated"
    exact = read_pkcs12(pfx, max_certs=3)
    assert len(exact.entries) == 3 and not exact.truncated and exact.detail is None


# ================================================================ key bags are skipped without being decoded
def test_key_bag_values_are_never_read_or_copied(ps, monkeypatch):
    pfx = structural_pfx([data_container([key_bag(CANARY, shrouded=True), cert_bag(LEAF),
                                          key_bag(CANARY2, shrouded=False), other_bag(OID_SECRET_BAG, CANARY2)])])
    spans = [(pfx.find(c), pfx.find(c) + len(c)) for c in (CANARY, CANARY2)]
    assert all(s >= 0 for s, _ in spans)
    touched = []                       # (buffer, from, to) for every .value/.raw access on ANY Tlv
    real_value, real_raw = Tlv.value, Tlv.raw
    monkeypatch.setattr(Tlv, "value", property(lambda self: (touched.append((self.buf, self.start, self.end)), real_value.fget(self))[1]))
    monkeypatch.setattr(Tlv, "raw", property(lambda self: (touched.append((self.buf, self.head, self.end)), real_raw.fget(self))[1]))
    result = read_pkcs12(pfx, max_certs=10)
    assert result.file_status == "ok" and fps(result) == [fp(LEAF)]       # garbage key bags did not matter
    in_pfx = [(a, b) for buf, a, b in touched if buf is pfx]              # the certificate parser uses its own buffer
    assert in_pfx and len(touched) > len(in_pfx), "the spy must see both the structure walk and the cert parse (control)"
    for (a, b) in in_pfx:
        for (s, e) in spans:
            assert b <= s or a >= e, f"bytes {a}..{b} of the PFX overlap a key bag value {s}..{e}"
    text = repr(result) + json.dumps(result.to_dict())
    for canary in (CANARY, CANARY2):
        assert canary.hex() not in text and base64.b64encode(canary).decode() not in text
        assert canary.decode("latin-1") not in text


def test_unknown_and_secret_bags_are_skipped_not_fatal(ps):
    pfx = structural_pfx([data_container([other_bag(OID_UNKNOWN, b"\xff" * 10), cert_bag(INTER),
                                          other_bag(OID_SECRET_BAG, b"\x00\x01"), cert_bag(ROOT)])])
    assert fps(read_pkcs12(pfx, max_certs=10)) == [fp(INTER), fp(ROOT)]


def test_non_x509_certificate_bags_are_ignored(ps):
    sdsi = _sdsi_cert_bag()
    pfx = structural_pfx([data_container([sdsi, cert_bag(LEAF)])])
    assert fps(read_pkcs12(pfx, max_certs=10)) == [fp(LEAF)]


def _sdsi_cert_bag():
    from certgen import _enc
    value = _enc(0x30, pfxgen.oid("2a864886f70d01091602") + _enc(0xA0, _enc(0x04, b"not-x509")))
    return _enc(0x30, pfxgen.oid(pfxgen.OID_CERT_BAG) + _enc(0xA0, value))


# ================================================================ what PowerShell receives
def test_powershell_receives_only_the_key_free_encrypted_containers(ps):
    key_container = data_container([key_bag(CANARY)])
    plain_cert_container = data_container([cert_bag(INTER)])
    encrypted = encrypted_container(ciphertext=b"CIPHERTEXT-A" * 5)
    pfx = structural_pfx([key_container, encrypted, plain_cert_container])
    ps.answer([LEAF, ROOT])
    result = read_pkcs12(pfx, max_certs=10)

    (call,) = ps.calls
    payload = call["payload"]
    assert containers_of(payload) == [encrypted]                          # exactly the encrypted container
    assert container_types(payload) == ["1.2.840.113549.1.7.6"] and not pfxgen.has_mac(payload)
    assert CANARY not in payload and key_container not in payload and plain_cert_container not in payload
    for i in range(0, len(key_container) - 16):
        assert key_container[i:i + 16] not in payload, "a slice of the key container reached PowerShell"
    assert call["timeout"] == 30
    assert fps(result) == [fp(INTER), fp(LEAF), fp(ROOT)]                # plain first, then OS-returned


def test_build_keyfree_pfx_is_deterministic_and_self_describing():
    enc = encrypted_container()
    payload = build_keyfree_pfx((enc,))
    assert payload == build_keyfree_pfx((enc,)) and containers_of(payload) == [enc]
    assert containers_of(build_keyfree_pfx(())) == []


def test_no_powershell_when_there_is_no_encrypted_container(ps):
    pfx = structural_pfx([data_container([key_bag(CANARY), cert_bag(LEAF)])])
    read_pkcs12(pfx, max_certs=10)
    assert ps.calls == []


def test_one_process_per_file_and_never_a_retry(ps):
    ps.result = completed(b"garbage", rc=1)
    result = read_pkcs12(encrypted_pfx(), max_certs=10)
    assert len(ps.calls) == 1 and (result.file_status, result.detail) == ("read_error", "powershell_failed")


def test_known_limitation_encrypted_containers_are_forwarded_without_being_inspected(ps):
    """Documents the limitation, so it cannot change silently: whatever sits inside an encryptedData
    container is invisible to Python. Both are forwarded; key *data* containers never are."""
    first, second = encrypted_container(ciphertext=b"\x01" * 40), encrypted_container(ciphertext=b"\x02" * 40)
    pfx = structural_pfx([data_container([key_bag(CANARY)]), first, second])
    ps.answer([LEAF])
    read_pkcs12(pfx, max_certs=10)
    assert containers_of(ps.calls[0]["payload"]) == [first, second]
    assert "KNOWN LIMITATION" in pfx_bridge.__doc__ and "encryptedData" in pfx_bridge.__doc__


def test_the_self_check_refuses_a_payload_that_is_not_exactly_the_selected_containers():
    enc = encrypted_container()
    key_container = data_container([key_bag(CANARY)])
    smuggled = structural_pfx([enc, key_container], mac=False)
    with pytest.raises(RuntimeError):
        pfx_bridge._assert_only_encrypted_containers(smuggled, (enc,))
    with pytest.raises(RuntimeError):
        pfx_bridge._assert_only_encrypted_containers(structural_pfx([enc], mac=True), (enc,))
    pfx_bridge._assert_only_encrypted_containers(build_keyfree_pfx((enc,)), (enc,))


# ================================================================ the process boundary itself
def test_argv_is_constant_and_carries_no_data(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured.update(argv=argv, kwargs=kwargs)
        return completed(ok_output([]))
    monkeypatch.setattr(pfx_bridge.subprocess, "run", fake_run)
    monkeypatch.setattr(pfx_bridge, "_powershell_path", lambda: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    monkeypatch.setenv("MY_SECRET_PASSWORD", "hunter2")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "abc123")
    payload = base64.b64encode(build_keyfree_pfx((encrypted_container(ciphertext=b"UNIQUE-PAYLOAD-MARKER" * 3),)))
    pfx_bridge._run_powershell(payload, 12)

    argv, kwargs = captured["argv"], captured["kwargs"]
    assert argv == ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-NoLogo", "-NoProfile",
                    "-NonInteractive", "-EncodedCommand", pfx_bridge._ENCODED_SCRIPT]
    assert payload not in b" ".join(a.encode() for a in argv) and b"UNIQUE-PAYLOAD-MARKER" not in b"".join(a.encode() for a in argv)
    assert kwargs["input"] == payload and kwargs["timeout"] == 12 and kwargs["shell"] is False
    assert "MY_SECRET_PASSWORD" not in kwargs["env"] and "AWS_SECRET_ACCESS_KEY" not in kwargs["env"]
    assert set(kwargs["env"]) <= {"SystemRoot", "windir", "SystemDrive", "TEMP", "TMP", "USERPROFILE", "APPDATA",
                                  "LOCALAPPDATA", "ProgramData", "ProgramFiles", "PATHEXT", "PATH"}
    assert "hunter2" not in repr(kwargs) and "abc123" not in repr(kwargs)


def test_powershell_is_located_in_system32_never_through_PATH(tmp_path, monkeypatch):
    fake_dir = tmp_path / "evil"
    fake_dir.mkdir()
    (fake_dir / "powershell.exe").write_bytes(b"MZ")
    monkeypatch.setenv("PATH", str(fake_dir) + os.pathsep + os.environ.get("PATH", ""))
    found = pfx_bridge._powershell_path()
    if os.name == "nt":
        expected = os.path.join(os.environ["SystemRoot"], "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        assert found == expected and str(fake_dir) not in found
    monkeypatch.delenv("SystemRoot", raising=False)
    assert pfx_bridge._powershell_path() is None


def test_the_script_is_constant_and_cannot_touch_passwords_keys_or_files():
    script = pfx_bridge._SCRIPT
    assert "Import($bytes, $null," in script and "EphemeralKeySet" in script
    for forbidden in ("SecureString", "Read-Host", "Get-Credential", "Get-Content", "Set-Content", "Out-File",
                      "Export", "PrivateKey", "HasPrivateKey", "GetRSAPrivateKey", "$env:", "Invoke-Expression",
                      "iex ", "Start-Process", "Invoke-WebRequest", "[IO.File]", "-Password"):
        assert forbidden not in script, forbidden
    assert pfx_bridge._ENCODED_SCRIPT == base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    assert "{0}" not in script.replace("'0x{0:X8}'", "")                  # no format-string interpolation points


# ================================================================ fail-safe refusals (PowerShell never called)
def refusal(result):
    return (result.file_status, result.detail)


def test_public_key_integrity_mode_is_refused(ps):
    pfx = structural_pfx([encrypted_container()], authsafe_type=OID_SIGNED_DATA)
    assert refusal(read_pkcs12(pfx, max_certs=10)) == ("unsupported", "pkcs12_password_protected")
    assert ps.calls == []


@pytest.mark.parametrize("make", [
    lambda: structural_pfx([_unknown_container(OID_ENVELOPED_DATA)]),
    lambda: structural_pfx([_unknown_container(OID_UNKNOWN)]),
    lambda: structural_pfx([data_container([key_bag(CANARY)]), encrypted_container(algorithm=OID_UNKNOWN)]),
    lambda: structural_pfx([encrypted_container(content_type=OID_SIGNED_DATA)]),
    lambda: structural_pfx([encrypted_container(), encrypted_container(algorithm=OID_UNKNOWN)]),
], ids=["enveloped", "unknown_container", "unknown_algorithm", "wrong_content_type", "one_bad_of_two"])
def test_layouts_that_cannot_be_reasoned_about_are_refused_before_any_os_call(ps, make):
    assert refusal(read_pkcs12(make(), max_certs=10)) == ("unsupported", "pkcs12_password_protected")
    assert ps.calls == []


def _unknown_container(oid_hex):
    from certgen import _enc
    return _enc(0x30, pfxgen.oid(oid_hex) + _enc(0xA0, _enc(0x04, b"opaque")))


def test_known_good_algorithms_are_accepted(ps):
    ps.answer([LEAF])
    for algorithm in (pfxgen.OID_PBE_3DES, OID_PBES2, "2a864886f70d010c0106", "2a864886f70d010c0102"):
        assert read_pkcs12(structural_pfx([encrypted_container(algorithm=algorithm)]), max_certs=10).file_status == "ok"
    assert len(ps.calls) == 4


@pytest.mark.parametrize("blob", [
    structural_pfx([encrypted_container()], version=2),
    structural_pfx([]) [:-3],
    b"\x30\x03\x02\x01\x03",
    b"\x30\x00",
    b"hello",
    b"",
], ids=["version2", "truncated", "no_authsafe", "empty_seq", "text", "empty"])
def test_malformed_structures_are_rejected_without_an_os_call(ps, blob):
    assert refusal(read_pkcs12(blob, max_certs=10)) == ("malformed", "pkcs12_malformed")
    assert ps.calls == []


def test_too_many_containers_is_malformed(ps):
    pfx = structural_pfx([data_container([cert_bag(LEAF)])] * (MAX_CONTAINERS + 1))
    assert refusal(read_pkcs12(pfx, max_certs=10)) == ("malformed", "pkcs12_malformed") and ps.calls == []


def test_every_truncation_of_a_structure_is_handled_without_an_os_call(ps):
    pfx = encrypted_pfx(plain_certs=(INTER,))
    for n in range(len(pfx)):
        result = read_pkcs12(pfx[:n], max_certs=10)
        assert result.file_status in ("malformed", "unsupported"), n
    assert ps.calls == []


def test_mutation_fuzz_never_sends_a_key_container(ps):
    key_container = data_container([key_bag(CANARY)])
    base = structural_pfx([key_container, data_container([cert_bag(INTER)]), encrypted_container()])
    rnd = random.Random(2026)
    ps.answer([LEAF])
    for _ in range(1500):
        mutated = bytearray(base)
        for _ in range(rnd.randrange(1, 5)):
            mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
        result = read_pkcs12(bytes(mutated), max_certs=10)
        assert result.detail != "internal_error" and CANARY not in repr(result).encode()
    for call in ps.calls:
        payload = call["payload"]
        assert CANARY not in payload and key_container not in payload
        assert set(container_types(payload)) == {"1.2.840.113549.1.7.6"}, "only encryptedData may ever be forwarded"


def test_random_garbage_never_crashes(ps):
    rnd = random.Random(5)
    for _ in range(2000):
        blob = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 120)))
        assert read_pkcs12(blob, max_certs=10).file_status in ("malformed", "unsupported", "no_certificate")
    assert ps.calls == []


# ================================================================ status mapping at the PowerShell boundary
def test_success_merges_plain_and_decrypted_certificates(ps):
    ps.answer([LEAF, ROOT])
    result = read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    assert (result.file_status, result.detail, result.total_certificates) == ("ok", None, 3)
    assert fps(result) == [fp(INTER), fp(LEAF), fp(ROOT)]


def test_os_decrypted_certificates_carry_the_integrity_warning_but_plain_ones_do_not(ps):
    from agent.observations import records_from_file_parse
    import datetime as dt
    ps.answer([LEAF])
    result = read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    plain, decrypted = result.entries
    assert plain.cert.warnings == () and decrypted.cert.warnings == (pfx_bridge.INTEGRITY_WARNING,)
    recs = records_from_file_parse("p", "f.pfx", "r", result, dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc), 30)
    assert [r["evidence_confidence"] for r in recs] == ["high", "medium"]
    assert [r["chain_index"] for r in recs] == [None, None]                 # PFX order is not chain order


def test_duplicates_returned_by_the_os_are_all_kept(ps):
    ps.answer([LEAF, LEAF, INTER])
    result = read_pkcs12(encrypted_pfx(plain_certs=(LEAF,)), max_certs=10)
    assert fps(result) == [fp(LEAF), fp(LEAF), fp(LEAF), fp(INTER)]       # plain + two from the OS: all sightings kept
    assert result.total_certificates == 4 and result.file_status == "ok"


def test_encrypted_only_pfx_with_no_certificates_inside(ps):
    ps.answer([])
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("no_certificate", "pkcs12_no_certificates")


@pytest.mark.parametrize("hresult,expected", [
    ("0x80070056", ("unsupported", "pkcs12_password_protected")),
    ("0x80090020", ("unsupported", "pkcs12_password_protected")),
    ("0x80092009", ("malformed", "pkcs12_malformed")),
    ("0x8009310B", ("malformed", "pkcs12_malformed")),
    ("0x80093102", ("malformed", "pkcs12_malformed")),
    ("0x80070057", ("read_error", "powershell_failed")),
    ("0xDEADBEEF", ("read_error", "powershell_failed")),
])
def test_hresult_mapping(ps, hresult, expected):
    ps.result = completed(error_output(hresult), rc=3)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == expected


def test_password_protected_file_is_never_retried_or_guessed(ps):
    ps.result = completed(error_output("0x80070056"), rc=3)
    read_pkcs12(encrypted_pfx(), max_certs=10)
    assert len(ps.calls) == 1
    assert b"password" not in ps.calls[0]["payload_b64"].lower() and "-Password" not in pfx_bridge._SCRIPT


def test_exit_code_alone_is_not_trusted_the_json_is(ps):
    ps.result = completed(ok_output([LEAF]), rc=0)
    assert read_pkcs12(encrypted_pfx(), max_certs=10).file_status == "ok"
    ps.result = completed(error_output("0x80070056"), rc=0)               # error JSON even with exit 0
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("unsupported", "pkcs12_password_protected")
    ps.result = completed(b"", rc=0)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_failed")


def test_unsupported_platform_only_affects_encrypted_containers(ps, monkeypatch):
    monkeypatch.setattr(pfx_bridge, "_is_windows", lambda: False)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("unsupported", "pkcs12_platform_unsupported")
    partial = read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    assert partial.file_status == "partial" and fps(partial) == [fp(INTER), None]
    assert partial.entries[1].detail == "pkcs12_platform_unsupported" and ps.calls == []


def test_powershell_unavailable(ps, monkeypatch):
    monkeypatch.setattr(pfx_bridge, "_powershell_path", lambda: None)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("unsupported", "powershell_unavailable")
    monkeypatch.setattr(pfx_bridge, "_powershell_path", lambda: "C:\\fake\\powershell.exe")
    ps.raises = FileNotFoundError("powershell.exe")
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("unsupported", "powershell_unavailable")


def test_process_start_failure_is_a_bridge_failure(ps):
    ps.raises = PermissionError(13, "denied")
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_failed")


def test_timeout_is_reported_and_the_configured_value_is_passed(ps):
    ps.raises = subprocess.TimeoutExpired(["powershell"], 30)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_timeout")
    assert ps.calls[0]["timeout"] == 30
    read_pkcs12(encrypted_pfx(), max_certs=10, timeout=7)
    assert ps.calls[1]["timeout"] == 7


def test_nonzero_exit_with_garbage_is_a_bridge_failure_and_stderr_is_never_forwarded(ps):
    ps.result = completed(b"Segmentation fault", rc=139, stderr=b"CANARY-STDERR secret")
    result = read_pkcs12(encrypted_pfx(), max_certs=10)
    assert refusal(result) == ("read_error", "powershell_failed")
    assert "CANARY" not in repr(result) and "Segmentation" not in repr(result)


def test_partial_when_the_os_part_fails_but_plain_certificates_exist(ps):
    ps.result = completed(error_output("0x80090020"), rc=3)
    result = read_pkcs12(encrypted_pfx(plain_certs=(INTER, ROOT)), max_certs=10)
    assert result.file_status == "partial"
    assert [e.parse_status for e in result.entries] == ["ok", "ok", "unsupported"]
    assert result.entries[2].detail == "pkcs12_password_protected" and result.entries[2].cert is None


# ================================================================ PowerShell output is untrusted
@pytest.mark.parametrize("stdout", [
    b"", b"not json", b"\xff\xfe\x00bad", b"[]", b"null", b"42", b'"ok"',
    b'{"status":"ok"}', b'{"status":"ok","certs":"AAAA"}', b'{"status":"ok","certs":[1]}',
    b'{"status":"ok","certs":[null]}', b'{"status":"ok","certs":[""]}', b'{"status":"ok","certs":["not base64!!"]}',
    b'{"status":"ok","certs":["QQ"]}', b'{"status":"ok","certs":["QQ=="],"extra":1}',
    # decodable ONLY by a lenient decoder that silently drops junk characters; the strict decoder must refuse
    b'{"status":"ok","certs":["QUJD!"]}', b'{"status":"ok","certs":["QU JD"]}',
    b'{"status":"ok","certs":["QUJD\\n"]}', b'{"status":"ok","certs":["QUJD-_"]}',
    b'{"status":"ok","certs":["Q\\u0055JD"]}'.replace(b"\\u0055", b"\xc3\xa9"),
    b'{"status":"nope","certs":[]}', b'{"status":"error"}', b'{"status":"error","hresult":5}',
    b'{"status":"error","hresult":"0x1234"}', b'{"status":"error","hresult":"0x80070056 "}',
    b'{"status":"error","hresult":"0x8007005g"}', b'{"status":"error","hresult":"0x80070056","certs":[]}',
    b'{"status":"ok","certs":[],"hresult":"0x80070056"}',
], ids=lambda b: b[:24].decode("latin-1"))
def test_malformed_powershell_output_is_rejected(ps, stdout):
    ps.result = completed(stdout, rc=0)
    result = read_pkcs12(encrypted_pfx(), max_certs=10)
    assert refusal(result) == ("read_error", "powershell_failed") and result.entries == ()


def test_oversized_or_overlong_output_is_rejected(ps):
    ps.result = completed(b" " * (pfx_bridge.MAX_OUTPUT_BYTES + 1))
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_failed")
    too_many = json.dumps({"status": "ok", "certs": ["QQ=="] * (pfx_bridge.MAX_RETURNED_CERTS + 1)}).encode()
    ps.result = completed(too_many)
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_failed")
    huge = base64.b64encode(b"\x30" * (pfx_bridge.MAX_CERT_BYTES + 1)).decode()
    ps.result = completed(json.dumps({"status": "ok", "certs": [huge]}).encode())
    assert refusal(read_pkcs12(encrypted_pfx(), max_certs=10)) == ("read_error", "powershell_failed")


def test_valid_base64_that_is_not_a_certificate_becomes_a_malformed_entry_not_a_crash(ps):
    ps.answer([LEAF, b"this is not DER", b"\x30\x03\x02\x01\x05", ROOT])
    result = read_pkcs12(encrypted_pfx(), max_certs=10)
    assert [e.parse_status for e in result.entries] == ["ok", "malformed", "malformed", "ok"]
    assert result.file_status == "partial" and fps(result) == [fp(LEAF), None, None, fp(ROOT)]
    assert result.entries[1].detail.startswith("x509_malformed")


def test_a_returned_certificate_is_revalidated_by_the_existing_parser(ps):
    mutated = bytearray(LEAF)
    mutated[len(mutated) // 2] ^= 0xFF
    ps.answer([bytes(mutated)])
    (entry,) = read_pkcs12(encrypted_pfx(), max_certs=10).entries
    # either rejected, or accepted with the fingerprint of the *mutated* bytes - never the original's
    assert entry.parse_status == "malformed" or entry.cert.sha256 != fp(LEAF)


def test_returned_certificate_count_is_capped_by_max_certs(ps):
    ps.answer([LEAF, INTER, ROOT, LEAF, INTER])
    cut = read_pkcs12(encrypted_pfx(plain_certs=(ROOT,)), max_certs=3)
    assert len(cut.entries) == 3 and cut.truncated and cut.detail == "bundle_truncated"
    assert fps(cut) == [fp(ROOT), fp(LEAF), fp(INTER)]


def test_plain_certificates_filling_the_cap_skip_the_os_call_but_report_truncation(ps):
    result = read_pkcs12(encrypted_pfx(plain_certs=(ROOT, INTER)), max_certs=2)
    assert ps.calls == [] and len(result.entries) == 2 and result.truncated


# ================================================================ no key material, passwords or noise anywhere
def test_nothing_is_printed_or_logged(ps, capsys, caplog):
    import logging
    caplog.set_level(logging.DEBUG)
    ps.answer([LEAF])
    read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    ps.result = completed(b"junk", rc=1, stderr=b"CANARY")
    read_pkcs12(encrypted_pfx(), max_certs=10)
    out = capsys.readouterr()
    assert out.out == "" and out.err == "" and caplog.text == ""


def test_results_serialize_as_strict_utf8_json(ps):
    ps.answer([LEAF, b"junk"])
    result = read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    blob = json.dumps(result.to_dict(), ensure_ascii=False).encode("utf-8")
    assert json.loads(blob)["format"] == "pkcs12"


@pytest.mark.parametrize("maker", [lambda: pfxgen.plain_with_key(), lambda: pfxgen.protected(),
                                   lambda: pfxgen.protected(legacy=True)], ids=["plain", "aes", "legacy"])
def test_no_private_key_bytes_in_any_result(ps, maker):
    pfx = maker()
    ps.result = completed(error_output("0x80090020"), rc=3)
    result = read_pkcs12(pfx, max_certs=10)
    text = json.dumps(result.to_dict()) + repr(result)
    secrets = pfxgen.shrouded_key_values(pfx)
    assert secrets, "fixture must contain a key bag"
    for value in secrets:
        for hexed in (value.hex(), base64.b64encode(value).decode()):
            for i in range(0, len(hexed) - 32, 3):
                assert hexed[i:i + 32] not in text
    # 40-byte windows: shorter ones can match the generic algorithm-identifier prefix that the key bag and the
    # certificate container legitimately share (same encryption scheme); a copied key bag matches everywhere.
    for payload in (c["payload"] for c in ps.calls):
        for value in secrets:
            for i in range(0, len(value) - 40):
                assert value[i:i + 40] not in payload, "key bag bytes reached the PowerShell payload"
            assert value not in payload


def test_source_bytes_are_never_modified(ps):
    original = pfxgen.protected()
    snapshot = bytes(original)
    ba = bytearray(original)
    read_pkcs12(bytes(ba), max_certs=10)
    read_pkcs12(ba, max_certs=10)
    assert bytes(ba) == snapshot == original


# ================================================================ static guards on the only process-starting module
def _bridge_tree():
    import ast
    import pathlib
    return ast.parse(pathlib.Path("agent/pfx_bridge.py").read_text(encoding="utf-8"))


def test_exactly_one_subprocess_call_with_shell_disabled_and_a_constant_argv():
    import ast
    tree = _bridge_tree()
    runs = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess" and n.func.attr == "run"]
    assert len(runs) == 1
    keywords = {k.arg: k.value for k in runs[0].keywords}
    assert isinstance(keywords["shell"], ast.Constant) and keywords["shell"].value is False
    assert "input" in keywords and "timeout" in keywords and "env" in keywords
    assert isinstance(runs[0].args[0], ast.Name) and runs[0].args[0].id == "argv"

    function = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_run_powershell")
    assigned = [n for n in ast.walk(function) if isinstance(n, ast.Assign) and n.targets[0].__class__ is ast.Name
                and n.targets[0].id == "argv"]
    assert len(assigned) == 1 and isinstance(assigned[0].value, ast.List)
    for element in assigned[0].value.elts:                   # constants plus the two named values only
        assert isinstance(element, ast.Constant) or (isinstance(element, ast.Name) and element.id in ("exe", "_ENCODED_SCRIPT"))
    assert not any(isinstance(n, (ast.JoinedStr, ast.Mod)) for n in ast.walk(assigned[0]))     # no f-strings / % formatting


def test_no_other_process_or_shell_apis_are_used():
    import ast
    names = {n.attr for n in ast.walk(_bridge_tree()) if isinstance(n, ast.Attribute)}
    assert not names & {"Popen", "call", "check_call", "check_output", "getoutput", "system", "popen", "startfile",
                        "spawn", "execv", "execl", "write_bytes", "write_text", "mkstemp", "mkdtemp", "NamedTemporaryFile"}
    imports = {a.name for n in ast.walk(_bridge_tree()) if isinstance(n, ast.Import) for a in n.names}
    assert "tempfile" not in imports and "shutil" not in imports and "ctypes" not in imports
    assert "cryptography" not in imports                      # the agent stays dependency-free


# ================================================================ integrity-warning semantics (provenance, not content)
WARNING = pfx_bridge.INTEGRITY_WARNING


def _records(result):
    import datetime as dt
    from agent.observations import records_from_file_parse
    return records_from_file_parse("p", "f.pfx", "r", result, dt.datetime(2025, 6, 1, tzinfo=dt.timezone.utc), 30)


def test_the_warning_follows_provenance_not_fingerprint_or_position(ps):
    # LEAF is present BOTH as a plain-container certificate and in what the OS returns.
    ps.answer([LEAF, ROOT])
    result = read_pkcs12(encrypted_pfx(plain_certs=(LEAF,)), max_certs=10)
    plain, from_os_a, from_os_b = result.entries
    assert plain.cert.sha256 == from_os_a.cert.sha256 == fp(LEAF)             # identical certificate identity
    assert plain.cert.warnings == ()                                          # ...but only the OS-path one is flagged
    assert from_os_a.cert.warnings == (WARNING,) and from_os_b.cert.warnings == (WARNING,)


@pytest.mark.parametrize("maker", [lambda: pfxgen.plain_with_key(), lambda: pfxgen.plain_certs_only((LEAF, INTER, ROOT)),
                                   lambda: pfxgen.plain_with_key(extra_ca=(LEAF, INTER))])
def test_plain_container_certificates_never_carry_the_warning(ps, maker):
    result = read_pkcs12(maker(), max_certs=10)
    assert result.entries and all(e.cert.warnings == () for e in result.entries)
    assert [r["evidence_confidence"] for r in _records(result)] == ["high"] * len(result.entries)
    assert ps.calls == [] and all(WARNING not in r["warnings"] for r in _records(result))


def test_every_certificate_from_the_os_path_is_flagged_and_capped_at_medium(ps):
    ps.answer([LEAF, INTER, ROOT])
    result = read_pkcs12(encrypted_pfx(plain_certs=(ROOT,)), max_certs=10)
    recs = _records(result)
    assert [r["evidence_confidence"] for r in recs] == ["high", "medium", "medium", "medium"]
    assert [WARNING in r["warnings"] for r in recs] == [False, True, True, True]
    assert all(r["parse_status"] == "ok" for r in recs)                       # never rejected for lack of integrity
    assert result.file_status == "ok"


def test_the_warning_is_added_after_existing_warnings_once(ps):
    from test_handbuilt import PADDED_MODULUS, build_v1, rsa_spki
    odd = build_v1(rsa_spki(PADDED_MODULUS), sig_oid="2a030405")             # parses, but with its own warning
    ps.answer([odd])
    (entry,) = read_pkcs12(encrypted_pfx(), max_certs=10).entries
    assert entry.cert.warnings == ("unknown_signature_algorithm", WARNING)
    assert entry.parse_status == "ok" and _records(read_pkcs12(encrypted_pfx(), max_certs=10))[0]["evidence_confidence"] == "medium"


def test_entries_without_a_certificate_carry_no_warning(ps):
    ps.answer([LEAF, b"not a certificate"])
    result = read_pkcs12(encrypted_pfx(), max_certs=10)
    good, bad = result.entries
    assert good.cert.warnings == (WARNING,) and bad.cert is None and bad.parse_status == "malformed"
    ps.result = completed(error_output("0x80070056"), rc=3)
    failed = read_pkcs12(encrypted_pfx(plain_certs=(INTER,)), max_certs=10)
    assert failed.entries[0].cert.warnings == () and failed.entries[1].cert is None      # the failure entry is not flagged


def test_truncated_bundles_flag_only_the_os_certificates_that_were_kept(ps):
    ps.answer([LEAF, INTER, ROOT])
    result = read_pkcs12(encrypted_pfx(plain_certs=(ROOT,)), max_certs=3)
    assert result.truncated and [e.cert.warnings for e in result.entries] == [(), (WARNING,), (WARNING,)]


def test_the_warning_is_a_fixed_safe_string_holding_no_material(ps):
    import re
    assert WARNING == "pkcs12_integrity_not_verified" and re.fullmatch("[a-z0-9_]+", WARNING)
    flagged = 0
    for pfx in (pfxgen.protected(), pfxgen.protected(legacy=True)):           # files that do go through the OS path
        ps.answer([LEAF, INTER])
        secrets = pfxgen.shrouded_key_values(pfx)
        assert secrets
        for rec in _records(read_pkcs12(pfx, max_certs=10)):
            assert WARNING in rec["warnings"]
            flagged += 1
            for warning in rec["warnings"]:
                assert re.fullmatch("[a-z0-9_]+", warning), warning           # nothing but a fixed identifier
                for value in secrets:
                    assert value.hex()[:24] not in warning and base64.b64encode(value).decode()[:24] not in warning
    assert flagged == 4


def test_documentation_states_exactly_what_is_and_is_not_verified():
    doc = " ".join(pfx_bridge.__doc__.split())
    for phrase in ("ORIGINAL PFX/P12 file may well carry MAC", "never verifies it",
                   "temporary, key-free PFX", "intentionally has NO MAC",
                   "CANNOT claim original-container integrity", "pkcs12_integrity_not_verified",
                   'caps its evidence confidence at "medium"', "NOT rejected", "plain `data` containers",
                   "never contains file, key or password material"):
        assert phrase in doc, phrase
    builder = " ".join(pfx_bridge.build_keyfree_pfx.__doc__.split())
    assert "intentionally has no MAC" in builder
