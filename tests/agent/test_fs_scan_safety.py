"""Scanner safety: private-key handling and read-only behaviour.

Guarantees under test:
  * key material never reaches a record or the summary, whatever the file layout/extension;
  * adding or removing key blocks never changes a file's records;
  * .pfx/.p12 and non-candidate files (.key, .txt, ...) are never opened;
  * the scan only ever opens files read-only and performs no mutating filesystem operation
    (proven with a Python audit hook), leaving every file and directory unchanged;
  * the scanner modules import/call nothing that could write, spawn or send data (static check).
"""
import ast
import contextlib
import hashlib
import json
import os
import pathlib
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs12

import certgen
import pemgen
from treegen import put, run_scan

CERT = pemgen.pem_encode(pemgen.der_of("sig_rsa_sha256"))
KEYS = pemgen.private_key_pems()
KEY_NAMES = list(KEYS)
MARKERS = ("PRIVATE", "ENCRYPTED", "BEGIN ", "-----", "DEK-Info", "Proc-Type", "OPENSSH")

# ---------------------------------------------------------------- audit hook (inert unless activated)
_WATCHED = {"open", "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.utime",
            "os.symlink", "os.link", "os.truncate", "os.mkfifo", "shutil.copyfile", "shutil.copymode",
            "shutil.copystat", "shutil.copytree", "shutil.move", "shutil.rmtree", "shutil.chown",
            "shutil.make_archive", "shutil.unpack_archive", "subprocess.Popen", "socket.connect",
            "socket.bind", "os.system", "os.exec", "os.posix_spawn"}
_state = {"active": False, "events": []}


def _hook(event, args):
    if _state["active"] and event in _WATCHED:
        _state["events"].append((event, args))


sys.addaudithook(_hook)


@contextlib.contextmanager
def audited():
    _state["events"] = []
    _state["active"] = True
    try:
        yield _state["events"]
    finally:
        _state["active"] = False


WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND


def assert_read_only(events, root):
    root = os.path.normcase(str(root))
    other = [e for e in events if e[0] != "open"]
    assert other == [], f"mutating/outbound operation during scan: {other}"
    for _, (path, mode, flags) in [e for e in events if e[0] == "open"]:
        if isinstance(path, (str, bytes)) and os.path.normcase(os.fsdecode(path)).startswith(root):
            assert mode in ("rb", "r") and not (flags & WRITE_FLAGS), (path, mode, flags)


def opened_in(events, root):
    root = os.path.normcase(str(root))
    return sorted(os.path.basename(os.fsdecode(p)) for e, (p, m, f) in events
                  if e == "open" and isinstance(p, (str, bytes)) and os.path.normcase(os.fsdecode(p)).startswith(root))


def snapshot(root):
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        snap[("dir", os.path.relpath(dirpath, root))] = sorted(dirnames + filenames)
        for name in filenames:
            p = os.path.join(dirpath, name)
            st = os.stat(p)
            with open(p, "rb") as fh:
                digest = hashlib.sha256(fh.read()).hexdigest()
            snap[("file", os.path.relpath(p, root))] = (digest, st.st_mtime_ns, st.st_size,
                                                        getattr(st, "st_file_attributes", 0))
    return snap


def haystack(records, summary):
    return json.dumps(records) + json.dumps(summary) + repr(records) + repr(summary)


# ---------------------------------------------------------------- key canaries across a whole tree
def key_tree(tmp_path, key_pem):
    key_der = None
    body = pemgen.key_body_text(key_pem)
    try:
        import base64
        key_der = base64.b64decode(body)
    except Exception:                                           # noqa: BLE001
        pass
    put(tmp_path, "certs/combined.pem", key_pem + CERT + key_pem)
    put(tmp_path, "certs/cert_then_key.crt", CERT + key_pem)
    put(tmp_path, "certs/key_then_cert.cer", key_pem + CERT)
    put(tmp_path, "keys/only.pem", key_pem)
    put(tmp_path, "keys/server.key", key_pem)
    put(tmp_path, "keys/server.txt", key_pem)
    put(tmp_path, "keys/store.pfx", key_pem)
    put(tmp_path, "keys/store.P12", key_pem)
    if key_der:
        put(tmp_path, "keys/private.der", key_der)             # a DER private key with a candidate extension
    return key_der


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_no_key_material_in_records_or_summary(tmp_path, key_name):
    key = KEYS[key_name]
    key_der = key_tree(tmp_path, key)
    canaries = pemgen.canary_set(key, n=32, step=2)
    if key_der:
        canaries |= pemgen.canary_windows(key_der.hex(), 32, 2)
    records, summary = run_scan(tmp_path)
    text = haystack(records, summary)
    assert not pemgen.leaked(text, canaries), key_name
    for marker in MARKERS:
        assert marker not in text, f"{key_name}: {marker!r} in output"
    ok = [r for r in records if r["parse_status"] == "ok"]
    assert len(ok) == 3 and {r["filename"] for r in ok} == {"combined.pem", "cert_then_key.crt", "key_then_cert.cer"}


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_pkcs12_and_non_candidate_files_are_never_opened(tmp_path, key_name):
    key_tree(tmp_path, KEYS[key_name])
    with audited() as events:
        records, _ = run_scan(tmp_path)
    opened = opened_in(events, tmp_path)
    assert "store.pfx" not in opened and "store.P12" not in opened
    assert "server.key" not in opened and "server.txt" not in opened
    assert {"combined.pem", "cert_then_key.crt", "key_then_cert.cer", "only.pem"} <= set(opened)
    assert_read_only(events, tmp_path)


@pytest.mark.parametrize("key_name", KEY_NAMES)
def test_key_blocks_never_change_a_files_records(tmp_path, key_name):
    key = KEYS[key_name]
    with_keys, plain = tmp_path / "with_keys", tmp_path / "plain"
    put(with_keys, "x/combined.pem", key + CERT + key)
    put(with_keys, "x/other.crt", CERT + key)
    put(with_keys, "y/tail.cer", pemgen.der_of("sig_rsa_sha256") + b"")           # DER, no key at all
    put(plain, "x/combined.pem", CERT)
    put(plain, "x/other.crt", CERT)
    put(plain, "y/tail.cer", pemgen.der_of("sig_rsa_sha256") + b"")

    def normalise(records, root):
        return [{k: (v.replace(str(root), "<root>") if isinstance(v, str) and k in ("path", "scan_root") else v)
                 for k, v in r.items()} for r in records]
    a_records, a_sum = run_scan(with_keys)
    b_records, b_sum = run_scan(plain)
    assert normalise(a_records, with_keys) == normalise(b_records, plain)
    for field in ("records", "records_by_status", "unique_certificates", "duplicate_observations",
                  "candidate_files", "files_read", "entries_visited", "directories_visited"):
        assert a_sum[field] == b_sum[field], field


def test_pfx_bytes_never_reach_the_output(tmp_path):
    cert = x509.load_der_x509_certificate(pemgen.der_of("key_rsa2048"))
    blobs = [pkcs12.serialize_key_and_certificates(b"n", certgen.key("rsa2048"), cert, None, enc)
             for enc in (ser.NoEncryption(), ser.BestAvailableEncryption(b"pw"))]
    for i, blob in enumerate(blobs):
        put(tmp_path, f"real{i}.pfx", blob)
        put(tmp_path, f"disguised{i}.crt", blob)                 # read and sniffed, but never parsed
    records, summary = run_scan(tmp_path)
    text = haystack(records, summary)
    import base64
    for blob in blobs:
        assert not pemgen.leaked(text, pemgen.canary_windows(blob.hex(), 32, 2))
        assert not pemgen.leaked(text, pemgen.canary_windows(base64.b64encode(blob).decode(), 32, 2))
    by = {r["filename"]: r["detail"] for r in records}
    assert by["real0.pfx"] == by["real1.pfx"] == "pkcs12_not_read"
    assert by["disguised0.crt"] == by["disguised1.crt"] == "pkcs12_not_handled_yet"


# ---------------------------------------------------------------- read-only proof
def rich_tree(root):
    put(root, "valid/a.pem", CERT)
    put(root, "valid/b.der", pemgen.der_of("key_p256"))
    put(root, "valid/c.pem", pemgen.private_key_pems()["pkcs8_ec"] + CERT)
    put(root, "broken/d.pem", b"-----BEGIN CERTIFICATE-----\nAAA*\n-----END CERTIFICATE-----\n")
    put(root, "broken/e.crt", b"")
    put(root, "broken/f.cer", b"\x30\x82\xff\xff garbage")
    put(root, "keys/g.pfx", b"pretend pfx")
    put(root, "keys/h.key", KEYS["pkcs8_rsa"])
    put(root, ".hidden/i.pem", CERT)
    put(root, "deep/a/b/c/j.pem", CERT)
    ro = put(root, "valid/readonly.pem", CERT)
    os.chmod(ro, 0o444)                                           # read-only attribute


def test_scan_changes_nothing_and_only_opens_read_only(tmp_path):
    rich_tree(tmp_path)
    before = snapshot(tmp_path)
    with audited() as events:
        records, summary = run_scan(tmp_path)
    after = snapshot(tmp_path)
    assert before == after, "a file, timestamp, attribute or directory listing changed during the scan"
    assert_read_only(events, tmp_path)
    assert len(records) >= 8 and summary["complete"]


def test_scan_of_a_nonexistent_or_unreadable_setup_still_mutates_nothing(tmp_path):
    rich_tree(tmp_path)
    with audited() as events:
        run_scan(tmp_path / "missing", tmp_path, tmp_path / "valid", max_entries=5)
    assert_read_only(events, tmp_path)


# ---------------------------------------------------------------- static allowlist
SCANNER_MODULES = {
    "fs_scan.py": {"__future__", "datetime", "os", "stat", "time", "cert_file", "observations", "scan_config"},
    "observations.py": {"__future__", "datetime", "cert_file", "x509_parse"},
    "scan_config.py": {"__future__", "ctypes", "os", "uuid", "dataclasses"},
}
FORBIDDEN_ATTRS = {"remove", "unlink", "rename", "replace", "rmdir", "removedirs", "mkdir", "makedirs",
                   "write", "writelines", "write_bytes", "write_text", "truncate", "chmod", "chown", "utime",
                   "symlink", "link", "copy", "copyfile", "copy2", "move", "rmtree", "system", "popen",
                   "startfile", "connect", "send", "sendall", "urlopen", "request", "getoutput", "check_output"}
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__", "print", "input"}


@pytest.mark.parametrize("module", list(SCANNER_MODULES))
def test_scanner_modules_import_only_what_they_need(module):
    tree = ast.parse((pathlib.Path("agent") / module).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module.split(".")[0] if node.module else "") if node.level == 0 else \
                imported.update({a.name for a in node.names} if not node.module else {node.module.split(".")[0]})
    assert imported <= SCANNER_MODULES[module], imported - SCANNER_MODULES[module]


@pytest.mark.parametrize("module", ["fs_scan.py", "observations.py"])
def test_scanner_modules_contain_no_write_or_outbound_calls(module):
    tree = ast.parse((pathlib.Path("agent") / module).read_text(encoding="utf-8"))
    opens = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            assert func.id not in FORBIDDEN_NAMES, f"{module}: call to {func.id}"
            if func.id == "open":
                opens += 1
                assert len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and node.args[1].value == "rb", f"{module}: open() must be called with mode 'rb'"
        elif isinstance(func, ast.Attribute):
            assert func.attr not in FORBIDDEN_ATTRS, f"{module}: call to .{func.attr}()"
    assert opens == (1 if module == "fs_scan.py" else 0)


# ---------------------------------------------------------------- output hygiene
def _walk(value):
    yield value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(k)
            yield from _walk(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _walk(v)


def test_records_and_summary_contain_only_plain_json_types(tmp_path):
    rich_tree(tmp_path)
    records, summary = run_scan(tmp_path)
    for item in _walk({"records": records, "summary": summary}):
        assert item is None or isinstance(item, (str, int, float, bool, list, dict)), type(item)
        assert not isinstance(item, (bytes, bytearray, memoryview))
    assert json.loads(json.dumps(records)) == records


def test_no_file_size_in_any_record(tmp_path):
    put(tmp_path, "small.pem", CERT)
    put(tmp_path, "padded.pem", CERT + b"# padding\n" * 200)
    records, _ = run_scan(tmp_path)
    assert all("size" not in k for r in records for k in r if k != "key_size")
    # the second sighting is (correctly) marked duplicate_in_scan; nothing else may differ
    stripped = [{k: v for k, v in r.items() if k not in ("path", "filename", "duplicate_in_scan")}
                for r in records]
    assert stripped[0] == stripped[1]                              # size differences are invisible
