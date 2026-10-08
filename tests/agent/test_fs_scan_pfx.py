"""Scan integration for PKCS#12: .pfx/.p12 (and disguised) files through the real scanner and, where noted,
the real PowerShell bridge. Covers records, duplicates, limits, read-only behaviour and key safety end to end."""
import base64
import json
import os
import subprocess

import pytest

import pemgen
import pfxgen
from agent import pfx_bridge
from agent.observations import RECORD_FIELDS
from pfxgen import fp
from test_fs_scan_safety import audited, haystack, snapshot
from treegen import put, run_scan

ROOT, INTER, LEAF = pfxgen.chain()
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell bridge")


def native(mode):
    try:
        return pfxgen.windows_native(mode)
    except pfxgen.FixtureUnavailable as e:
        pytest.skip(f"cannot create a Windows-native fixture here: {e}")


@pytest.fixture
def ps_calls(monkeypatch):
    """Count (and pass through) every real PowerShell invocation."""
    calls = []
    real = pfx_bridge._run_powershell

    def wrapper(payload_b64, timeout):
        calls.append(base64.b64decode(payload_b64))
        return real(payload_b64, timeout)
    monkeypatch.setattr(pfx_bridge, "_run_powershell", wrapper)
    return calls


def by_name(records):
    out = {}
    for r in records:
        out.setdefault(r["filename"], []).append(r)
    return out


# ================================================================ extensions, formats, record shape
def test_pfx_and_p12_and_disguised_files_all_yield_certificate_records(tmp_path, ps_calls):
    plain = pfxgen.plain_with_key()
    put(tmp_path, "server.pfx", plain)
    put(tmp_path, "CLIENT.P12", plain)
    put(tmp_path, "sneaky.crt", plain)
    put(tmp_path, "notes.txt", plain)                              # not a candidate: never read
    records, summary = run_scan(tmp_path)
    got = by_name(records)
    assert sorted(got) == ["CLIENT.P12", "server.pfx", "sneaky.crt"]
    for name, recs in got.items():
        assert len(recs) == 3 and all(r["format"] == "pkcs12" and r["parse_status"] == "ok" for r in recs), name
        assert sorted(r["sha256"] for r in recs) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert got["sneaky.crt"][0]["extension_mismatch"] is True and got["server.pfx"][0]["extension_mismatch"] is False
    assert summary["files_read"] == 3 and summary["candidate_files"] == 3 and ps_calls == []     # plain: no OS call


def test_pkcs12_records_never_claim_a_chain_position(tmp_path):
    put(tmp_path, "a.pfx", pfxgen.plain_with_key())
    put(tmp_path, "b.pem", b"".join(pemgen.pem_encode(d) for d in (LEAF, INTER, ROOT)))
    records, _ = run_scan(tmp_path)
    pfx = [r for r in records if r["filename"] == "a.pfx"]
    pem = [r for r in records if r["filename"] == "b.pem"]
    assert all(r["chain_index"] is None and r["chain_total"] == 3 for r in pfx)
    assert [r["chain_index"] for r in pem] == [0, 1, 2]                                  # PEM order is evidence; PFX order is not
    assert sorted(r["chain_role"] for r in pfx) == ["ca", "leaf", "self_signed"]         # role is about the certificate itself


def test_every_pkcs12_record_matches_the_schema(tmp_path, ps_calls):
    put(tmp_path, "plain.pfx", pfxgen.plain_with_key())
    put(tmp_path, "protected.pfx", pfxgen.protected())
    put(tmp_path, "broken.p12", pfxgen.structural_pfx([b"\x30\x03\x01\x01\xff"]))
    records, _ = run_scan(tmp_path)
    assert records and all(tuple(r) == RECORD_FIELDS for r in records)


# ================================================================ statuses through the scanner
@windows_only
def test_windows_exported_pfx_through_the_real_bridge(tmp_path, ps_calls):
    put(tmp_path, "exported.pfx", native("chain"))
    put(tmp_path, "trust.p12", native("certs_only"))
    records, summary = run_scan(tmp_path)
    got = by_name(records)
    assert sorted(r["sha256"] for r in got["exported.pfx"]) == sorted([fp(ROOT), fp(INTER), fp(LEAF)])
    assert sorted(r["sha256"] for r in got["trust.p12"]) == sorted([fp(ROOT), fp(INTER)])
    assert all(r["parse_status"] == "ok" and r["chain_index"] is None for r in records)
    assert all("pkcs12_integrity_not_verified" in r["warnings"] and r["evidence_confidence"] == "medium"
               for r in records)                                                       # decrypted by the OS: capped
    assert len(ps_calls) == 2 and summary["complete"]                                  # one process per encrypted file


@windows_only
def test_one_process_per_encrypted_file_and_none_for_other_files(tmp_path, ps_calls):
    put(tmp_path, "a.pfx", native("chain"))
    put(tmp_path, "b.pfx", native("certs_only"))
    put(tmp_path, "c.pfx", pfxgen.plain_with_key())                                    # plain container: no process
    put(tmp_path, "d.pem", pemgen.pem_encode(LEAF))
    put(tmp_path, "e.der", LEAF)
    run_scan(tmp_path)
    assert len(ps_calls) == 2
    for payload in ps_calls:
        assert set(pfxgen.container_types(payload)) == {"1.2.840.113549.1.7.6"}       # never a key container


@windows_only
@pytest.mark.parametrize("maker", [lambda: pfxgen.protected(), lambda: pfxgen.protected(legacy=True),
                                   lambda: native("protected")], ids=["aes", "3des", "windows_native"])
def test_password_protected_files_are_reported_never_guessed(tmp_path, ps_calls, maker):
    put(tmp_path, "locked.pfx", maker())
    (rec,), summary = run_scan(tmp_path)
    assert (rec["format"], rec["parse_status"], rec["detail"]) == ("pkcs12", "unsupported", "pkcs12_password_protected")
    assert rec["sha256"] is None and rec["evidence_confidence"] == "low"
    assert rec["chain_index"] is None and rec["chain_total"] is None
    assert len(ps_calls) == 1 and summary["complete"]


def test_structurally_corrupt_pkcs12_is_malformed_and_never_reaches_the_os(tmp_path, ps_calls):
    # starts like a PFX (so it is recognised as one) but the inside is broken
    put(tmp_path, "broken.pfx", pfxgen.structural_pfx([b"\x30\x03\x01\x01\xff"]))
    put(tmp_path, "truncated.p12", pfxgen.plain_with_key()[:200])                       # cut: not even recognisable
    records, _ = run_scan(tmp_path)
    got = {r["filename"]: (r["format"], r["parse_status"], r["detail"]) for r in records}
    assert got["broken.pfx"] == ("pkcs12", "malformed", "pkcs12_malformed")
    assert got["truncated.p12"] == ("unknown", "malformed", "unrecognized_content")
    assert ps_calls == []


def test_a_pfx_extension_on_ordinary_certificates_is_still_handled_by_content(tmp_path, ps_calls):
    put(tmp_path, "really_pem.pfx", pemgen.pem_encode(LEAF))
    put(tmp_path, "really_der.p12", INTER)
    records, _ = run_scan(tmp_path)
    got = {r["filename"]: (r["format"], r["parse_status"], r["extension_mismatch"]) for r in records}
    assert got == {"really_pem.pfx": ("pem", "ok", True), "really_der.p12": ("der", "ok", True)}
    assert ps_calls == []


def test_platform_and_bridge_failures_are_per_file_and_the_scan_continues(tmp_path, monkeypatch):
    put(tmp_path, "a_plain.pfx", pfxgen.plain_with_key())
    put(tmp_path, "b_enc.pfx", pfxgen.protected())
    put(tmp_path, "c_after.pem", pemgen.pem_encode(LEAF))
    scenarios = {
        "platform": (lambda: monkeypatch.setattr(pfx_bridge, "_is_windows", lambda: False),
                     ("unsupported", "pkcs12_platform_unsupported")),
        "no_powershell": (lambda: monkeypatch.setattr(pfx_bridge, "_powershell_path", lambda: None),
                          ("unsupported", "powershell_unavailable")),
        "timeout": (lambda: monkeypatch.setattr(pfx_bridge, "_run_powershell", _raise(subprocess.TimeoutExpired("ps", 30))),
                    ("read_error", "powershell_timeout")),
        "crash": (lambda: monkeypatch.setattr(pfx_bridge, "_run_powershell", _raise(PermissionError(13, "no"))),
                  ("read_error", "powershell_failed")),
    }
    for name, (arrange, expected) in scenarios.items():
        monkeypatch.undo()
        arrange()
        records, summary = run_scan(tmp_path)
        got = by_name(records)
        assert len(got["a_plain.pfx"]) == 3 and all(r["parse_status"] == "ok" for r in got["a_plain.pfx"]), name
        assert (got["b_enc.pfx"][0]["parse_status"], got["b_enc.pfx"][0]["detail"]) == expected, name
        assert got["c_after.pem"][0]["parse_status"] == "ok" and summary["complete"], name


def _raise(exc):
    def boom(*a, **k):
        raise exc
    return boom


# ================================================================ duplicates keep every sighting
def test_the_same_certificate_in_several_files_and_formats_is_reported_every_time(tmp_path):
    put(tmp_path, "a.pfx", pfxgen.plain_certs_only((LEAF,)))
    put(tmp_path, "b.p12", pfxgen.plain_certs_only((LEAF,)))
    put(tmp_path, "c.pem", pemgen.pem_encode(LEAF))
    put(tmp_path, "d.der", LEAF)
    records, summary = run_scan(tmp_path)
    assert [r["filename"] for r in records] == ["a.pfx", "b.p12", "c.pem", "d.der"]
    assert {r["sha256"] for r in records} == {fp(LEAF)}                               # one certificate identity
    assert [r["duplicate_in_scan"] for r in records] == [False, True, True, True]     # four sightings, none discarded
    assert summary["records"] == 4 and summary["unique_certificates"] == 1 and summary["duplicate_observations"] == 3


def test_duplicates_inside_one_pfx_are_all_kept_and_marked(tmp_path):
    put(tmp_path, "twice.pfx", pfxgen.plain_with_key(extra_ca=(LEAF, INTER)))
    records, summary = run_scan(tmp_path)
    assert len(records) == 3 and sorted(r["sha256"] for r in records) == sorted([fp(LEAF), fp(LEAF), fp(INTER)])
    assert sum(r["duplicate_in_scan"] for r in records) == 1 and summary["duplicate_observations"] == 1


# ================================================================ limits
def test_max_certs_per_file_is_respected_for_pkcs12(tmp_path):
    put(tmp_path, "big.pfx", pfxgen.plain_with_key())
    records, summary = run_scan(tmp_path, max_certs_per_file=2)
    assert len(records) == 2 and summary["bundles_truncated"] == 1


def test_oversized_pkcs12_is_reported_without_being_read(tmp_path, monkeypatch):
    import builtins
    put(tmp_path, "huge.pfx", pfxgen.plain_with_key() + b"\x00" * 5000)
    opened = []
    real = builtins.open
    monkeypatch.setattr(builtins, "open", lambda f, m="r", *a, **k: (opened.append(os.fspath(f)), real(f, m, *a, **k))[1])
    (rec,), _ = run_scan(tmp_path, max_file_bytes=2000)
    assert (rec["parse_status"], rec["detail"]) == ("too_large", "file_too_large") and opened == []


# ================================================================ the source is never modified; read-only; no temp files
@windows_only
def test_scan_leaves_every_source_file_unchanged_and_only_reads(tmp_path):
    put(tmp_path, "keys/a.pfx", native("chain"))
    put(tmp_path, "keys/b.p12", pfxgen.protected())
    put(tmp_path, "keys/c.pfx", pfxgen.plain_with_key())
    put(tmp_path, "keys/d.crt", pfxgen.protected(legacy=True))
    before = snapshot(tmp_path)
    with audited() as events:
        records, summary = run_scan(tmp_path)
    assert snapshot(tmp_path) == before, "a PFX/P12 file or directory listing changed"
    assert {e[0] for e in events} <= {"open", "subprocess.Popen"}, [e[0] for e in events]
    assert sum(e[0] == "subprocess.Popen" for e in events) == 4 - 1                   # a, b, d need the OS; c is plain
    root = os.path.normcase(str(tmp_path))
    for name, (path, mode, flags) in [e for e in events if e[0] == "open"]:
        if isinstance(path, int):
            continue                                    # a pipe to the child process, not a file
        if os.path.normcase(os.fsdecode(path)).startswith(root):
            # the audit event reports a binary read as mode "r"; the flags are what prove it is read-only
            assert mode in ("rb", "r") and not (flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
    assert sorted(os.listdir(tmp_path)) == ["keys"] and len(records) >= 4 and summary["complete"]


@windows_only
def test_no_temporary_files_during_a_scan(tmp_path, monkeypatch):
    isolated = tmp_path / "tmp"
    isolated.mkdir()
    for var in ("TEMP", "TMP"):
        monkeypatch.setenv(var, str(isolated))
    tree = tmp_path / "tree"
    put(tree, "a.pfx", native("chain"))
    put(tree, "b.pfx", pfxgen.protected())
    run_scan(tree)
    assert list(isolated.iterdir()) == []


# ================================================================ private-key safety, end to end
def _canaries(pfx):
    out = set()
    for value in pfxgen.shrouded_key_values(pfx):
        for text in (value.hex(), base64.b64encode(value).decode()):
            out |= {text[i:i + 32] for i in range(0, len(text) - 32, 7)}
    return out


@pytest.mark.parametrize("name", ["plain", "aes", "3des", "native", "native_protected"])
def test_no_key_material_in_records_or_summary(tmp_path, capsys, caplog, name):
    if name.startswith("native") and os.name != "nt":
        pytest.skip("Windows only")
    pfx = {"plain": pfxgen.plain_with_key, "aes": pfxgen.protected, "3des": lambda: pfxgen.protected(legacy=True),
           "native": lambda: native("chain"), "native_protected": lambda: native("protected")}[name]()
    put(tmp_path, "k/store.pfx", pfx)
    put(tmp_path, "k/disguised.crt", pfx)
    put(tmp_path, "k/store.P12", pfx)
    records, summary = run_scan(tmp_path)
    text = haystack(records, summary)
    assert not pemgen.leaked(text, _canaries(pfx)), name
    if name == "plain":                                         # the plain PKCS#8 key is also searchable directly
        key = pfxgen.private_key_der()
        assert not pemgen.leaked(text, {key.hex()[i:i + 32] for i in range(0, 400, 7)})
        assert not pemgen.leaked(text, {base64.b64encode(key).decode()[i:i + 32] for i in range(0, 400, 7)})
    for marker in ("PRIVATE", "ENCRYPTED", "BEGIN ", "-----", "shrouded", "keyBag"):
        assert marker not in text, marker
    out = capsys.readouterr()
    assert out.out == "" and out.err == "" and caplog.text == ""


def test_key_bags_with_hostile_contents_never_break_or_leak(tmp_path):
    canary = bytes((i * 29 + 3) % 251 for i in range(120))
    hostile = pfxgen.structural_pfx([pfxgen.data_container([pfxgen.key_bag(canary), pfxgen.cert_bag(LEAF),
                                                            pfxgen.key_bag(canary, shrouded=False)])])
    put(tmp_path, "hostile.pfx", hostile)
    (rec,), summary = run_scan(tmp_path)
    text = haystack([rec], summary)
    assert rec["sha256"] == fp(LEAF) and rec["parse_status"] == "ok"
    assert canary.hex() not in text and base64.b64encode(canary).decode() not in text


# ================================================================ strict UTF-8 / JSON
def test_records_are_strict_utf8_json_including_odd_file_names(tmp_path):
    put(tmp_path, "bad\ud800name.pfx", pfxgen.plain_with_key())
    put(tmp_path, "sub\udc80dir/ünï 😀.p12", pfxgen.protected())
    records, summary = run_scan(tmp_path)
    blob = json.dumps({"records": records, "summary": summary}, ensure_ascii=False).encode("utf-8")
    assert blob
    names = sorted({r["filename"] for r in records})
    assert names == ["bad\\ud800name.pfx", "ünï 😀.p12"]
    for r in records:
        for field in ("path", "filename", "scan_root"):
            r[field].encode("utf-8")


# ================================================================ integrity warning through the scanner
@windows_only
def test_scanner_records_flag_only_os_derived_certificates(tmp_path):
    mixed = pfxgen.structural_pfx([pfxgen.data_container([pfxgen.cert_bag(INTER)]),
                                   pfxgen.containers_of(native("chain"))[-1]])
    put(tmp_path, "mixed.pfx", mixed)
    put(tmp_path, "plain.pfx", pfxgen.plain_with_key())
    records, summary = run_scan(tmp_path)
    got = by_name(records)
    assert all(r["warnings"] == [] and r["evidence_confidence"] == "high" for r in got["plain.pfx"])
    first, *rest = got["mixed.pfx"]
    assert first["sha256"] == fp(INTER) and first["warnings"] == [] and first["evidence_confidence"] == "high"
    assert len(rest) == 3 and all(r["warnings"] == ["pkcs12_integrity_not_verified"] for r in rest)
    assert all(r["evidence_confidence"] == "medium" and r["parse_status"] == "ok" for r in rest)
    assert all(r["chain_index"] is None for r in records) and summary["complete"]
    text = json.dumps(records)
    assert "integrity" in text and "BEGIN" not in text
