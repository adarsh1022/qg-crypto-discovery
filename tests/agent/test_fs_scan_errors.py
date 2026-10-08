"""Scan: access errors, vanished/locked files, unexpected exceptions, links and placeholders."""
import builtins
import json
import os

import pytest

import pemgen
from agent import fs_scan
from agent.fs_scan import error_code
from treegen import (exclusive_lock, make_junction, offline_attribute, put, run_scan, try_symlink)

PEM = pemgen.pem_encode(pemgen.der_of("key_p256"))
windows_only = pytest.mark.skipif(os.name != "nt", reason="needs Windows filesystem features")


def names(records):
    return [r["filename"] for r in records]


def fail_open(monkeypatch, predicate, make_exc):
    real = builtins.open

    def fake(file, mode="r", *a, **k):
        path = os.fspath(file)
        if predicate(path):
            raise make_exc(path)
        return real(file, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", fake)


def fail_scandir(monkeypatch, predicate, make_exc):
    real = os.scandir

    def fake(path, *a, **k):
        if predicate(os.fspath(path)):
            raise make_exc(os.fspath(path))
        return real(path, *a, **k)
    monkeypatch.setattr(os, "scandir", fake)


# ---------------------------------------------------------------- error codes
def test_error_code_format():
    assert error_code(PermissionError(13, "denied", None, 5)) == "PermissionError:WinError 5"
    assert error_code(FileNotFoundError(2, "gone", None, 2)) == "FileNotFoundError:WinError 2"
    assert error_code(OSError(22, "weird")) == "OSError:errno 22"


# ---------------------------------------------------------------- unreadable directories
def test_unreadable_directory_is_reported_and_siblings_are_still_scanned(tmp_path, monkeypatch):
    put(tmp_path, "a/x.pem", PEM)
    put(tmp_path, "locked/y.pem", PEM)
    put(tmp_path, "z/w.pem", PEM)
    fail_scandir(monkeypatch, lambda p: p.endswith("locked"), lambda p: PermissionError(13, "denied", p, 5))
    records, summary = run_scan(tmp_path)
    assert names(records) == ["x.pem", "w.pem"]
    assert summary["errors"] == [{"path": str(tmp_path / "locked"), "kind": "listdir",
                                  "code": "PermissionError:WinError 5"}]
    assert summary["errors_total"] == 1 and summary["directories_visited"] == 3
    assert summary["complete"] is True and summary["roots"][0]["status"] == "scanned"


def test_error_raised_while_iterating_a_directory(tmp_path, monkeypatch):
    put(tmp_path, "bad/x.pem", PEM)
    put(tmp_path, "good/y.pem", PEM)

    class Exploding:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def __iter__(self):
            raise OSError(1117, "I/O device error", None, 1117)

    real = os.scandir
    monkeypatch.setattr(os, "scandir", lambda p, *a, **k: Exploding() if os.fspath(p).endswith("bad") else real(p, *a, **k))
    records, summary = run_scan(tmp_path)
    assert names(records) == ["y.pem"] and summary["errors"][0]["code"] == "OSError:WinError 1117"


def test_error_list_is_capped_but_counted(tmp_path, monkeypatch):
    for i in range(1200):
        (tmp_path / f"d{i:04d}").mkdir()
    root = os.path.normpath(str(tmp_path))
    fail_scandir(monkeypatch, lambda p: os.path.normpath(p) != root, lambda p: PermissionError(13, "x", p, 5))
    records, summary = run_scan(tmp_path)
    assert summary["errors_total"] == 1200 and len(summary["errors"]) == fs_scan.MAX_LISTED_ERRORS == 1000
    assert summary["directories_visited"] == 1 and summary["complete"]


def test_unreadable_root_is_reported_and_other_roots_still_scan(tmp_path, monkeypatch):
    put(tmp_path, "locked/a.pem", PEM)
    put(tmp_path, "open/b.pem", PEM)
    real = os.stat
    target = os.path.normpath(str(tmp_path / "locked"))

    def fake(path, *a, **k):
        if isinstance(path, str) and os.path.normpath(path) == target:
            raise PermissionError(13, "denied", path, 5)
        return real(path, *a, **k)
    monkeypatch.setattr(os, "stat", fake)
    records, summary = run_scan(tmp_path / "locked", tmp_path / "open")
    assert names(records) == ["b.pem"]
    assert [r["status"] for r in summary["roots"]] == ["access_denied", "scanned"]
    assert summary["errors"][0]["kind"] == "root"


# ---------------------------------------------------------------- unreadable files
def test_permission_denied_on_a_file(tmp_path, monkeypatch):
    put(tmp_path, "denied.pem", PEM)
    put(tmp_path, "fine.pem", PEM)
    fail_open(monkeypatch, lambda p: p.endswith("denied.pem"), lambda p: PermissionError(13, "denied", p, 5))
    records, summary = run_scan(tmp_path)
    by = {r["filename"]: r for r in records}
    bad = by["denied.pem"]
    assert (bad["parse_status"], bad["detail"], bad["access_error"]) == (
        "access_denied", "read_failed", "PermissionError:WinError 5")
    assert bad["evidence_confidence"] == "low" and bad["sha256"] is None and bad["format"] == "unknown"
    assert by["fine.pem"]["parse_status"] == "ok"
    assert summary["records_by_status"] == {"access_denied": 1, "ok": 1}
    assert summary["errors"][0]["kind"] == "read" and summary["complete"]


def test_file_that_vanishes_between_listing_and_reading(tmp_path, monkeypatch):
    put(tmp_path, "gone.pem", PEM)
    fail_open(monkeypatch, lambda p: p.endswith("gone.pem"), lambda p: FileNotFoundError(2, "gone", p, 2))
    (rec,), _ = run_scan(tmp_path)
    assert (rec["parse_status"], rec["access_error"]) == ("read_error", "FileNotFoundError:WinError 2")


def test_other_os_errors_are_read_errors(tmp_path, monkeypatch):
    put(tmp_path, "weird.pem", PEM)
    fail_open(monkeypatch, lambda p: p.endswith("weird.pem"), lambda p: OSError(22, "weird"))
    (rec,), _ = run_scan(tmp_path)
    assert (rec["parse_status"], rec["access_error"]) == ("read_error", "OSError:errno 22")


@windows_only
def test_real_sharing_violation_on_a_locked_file(tmp_path):
    locked = put(tmp_path, "locked.pem", PEM)
    put(tmp_path, "free.pem", PEM)
    with exclusive_lock(locked):
        records, summary = run_scan(tmp_path)
    by = {r["filename"]: r for r in records}
    # Documented limitation: Python's open() reports a sharing violation exactly like a permission
    # denial (PermissionError, errno 13, no winerror), so the two cannot be told apart here.
    assert (by["locked.pem"]["parse_status"], by["locked.pem"]["access_error"]) == (
        "access_denied", "PermissionError:errno 13")
    assert by["free.pem"]["parse_status"] == "ok" and summary["complete"]
    again, _ = run_scan(tmp_path)                                            # lock released -> readable
    assert [r["parse_status"] for r in again] == ["ok", "ok"]


def test_os_error_text_never_reaches_the_output(tmp_path, monkeypatch):
    put(tmp_path, "a.pem", PEM)
    put(tmp_path, "d/b.pem", PEM)
    fail_open(monkeypatch, lambda p: p.endswith("a.pem"),
              lambda p: PermissionError(13, "CANARY-STRERROR", "C:\\CANARY-FILENAME", 5))
    fail_scandir(monkeypatch, lambda p: p.endswith("d"), lambda p: OSError(5, "CANARY-STRERROR2", "CANARY-F2", 5))
    records, summary = run_scan(tmp_path)
    blob = json.dumps(records) + json.dumps(summary)
    assert "CANARY" not in blob


def test_unexpected_exception_in_the_parser_is_isolated(tmp_path, monkeypatch):
    put(tmp_path, "bad.pem", PEM)
    put(tmp_path, "good.pem", PEM)
    real = fs_scan.parse_cert_bytes

    def flaky(data, **kw):
        if kw["filename_hint"] == "bad.pem":
            raise RuntimeError("secret-boom")
        return real(data, **kw)
    monkeypatch.setattr(fs_scan, "parse_cert_bytes", flaky)
    records, summary = run_scan(tmp_path)
    by = {r["filename"]: r for r in records}
    assert (by["bad.pem"]["parse_status"], by["bad.pem"]["detail"]) == ("read_error", "internal_error")
    assert by["good.pem"]["parse_status"] == "ok" and summary["complete"]
    assert "secret-boom" not in json.dumps(records) + json.dumps(summary)


def test_unexpected_exception_while_reading_is_isolated(tmp_path, monkeypatch):
    put(tmp_path, "bad.pem", PEM)
    put(tmp_path, "good.pem", PEM)
    fail_open(monkeypatch, lambda p: p.endswith("bad.pem"), lambda p: RuntimeError("secret-boom"))
    records, _ = run_scan(tmp_path)
    by = {r["filename"]: r for r in records}
    assert by["bad.pem"]["detail"] == "internal_error" and by["good.pem"]["parse_status"] == "ok"
    assert "secret-boom" not in json.dumps(records)


# ---------------------------------------------------------------- junctions, symlinks, loops
@windows_only
def test_junction_loop_terminates_and_is_not_followed(tmp_path):
    root = tmp_path / "root"
    put(root, "a/c.pem", PEM)
    loop = root / "a" / "loop"
    assert make_junction(loop, root), "mklink /J failed"
    try:
        records, summary = run_scan(root)
    finally:
        os.rmdir(loop)
    assert names(records) == ["c.pem"]
    assert summary["skipped"]["reparse_dir"] == 1 and summary["complete"]
    assert summary["directories_visited"] == 2


@windows_only
def test_junction_to_an_outside_directory_is_not_followed(tmp_path):
    outside = tmp_path / "outside"
    put(outside, "o.pem", PEM)
    root = tmp_path / "root"
    put(root, "inside.pem", PEM)
    link = root / "link"
    assert make_junction(link, outside)
    try:
        records, summary = run_scan(root)
    finally:
        os.rmdir(link)
    assert names(records) == ["inside.pem"] and summary["skipped"]["reparse_dir"] == 1


@windows_only
def test_an_explicit_junction_root_is_scanned_as_intended(tmp_path):
    real = tmp_path / "real"
    put(real, "sub/a.pem", PEM)
    link = tmp_path / "link"
    assert make_junction(link, real)
    try:
        records, summary = run_scan(link)
        assert names(records) == ["a.pem"]
        assert records[0]["scan_root"] == os.path.normpath(str(link))
        assert records[0]["path"].startswith(str(link))
        both, both_summary = run_scan(link, real)                          # same directory twice -> one scan
        assert names(both) == ["a.pem"] and both_summary["skipped"]["root_overlap"] == 1
    finally:
        os.rmdir(link)


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    put(outside, "o.pem", PEM)
    root = tmp_path / "root"
    put(root, "plain.pem", PEM)
    dir_link, file_link = root / "dirlink", root / "filelink.pem"
    made_dir = try_symlink(dir_link, outside, True)
    made_file = try_symlink(file_link, outside / "o.pem", False)
    if not (made_dir and made_file):
        pytest.skip("creating symlinks needs Developer Mode or elevation on this machine")
    records, summary = run_scan(root)
    assert names(records) == ["plain.pem"]
    assert summary["skipped"]["reparse_dir"] == 1 and summary["skipped"]["reparse_file"] == 1


# ---------------------------------------------------------------- cloud placeholders
@windows_only
def test_cloud_placeholder_candidate_is_skipped_and_never_opened(tmp_path, monkeypatch):
    placeholder = put(tmp_path, "cloud.pem", PEM)
    put(tmp_path, "local.pem", PEM)
    opened = []
    real = builtins.open

    def spy(file, mode="r", *a, **k):
        opened.append(os.path.basename(os.fspath(file)))
        return real(file, mode, *a, **k)
    with offline_attribute(placeholder):
        monkeypatch.setattr(builtins, "open", spy)
        records, summary = run_scan(tmp_path)
        monkeypatch.undo()
    by = {r["filename"]: r for r in records}
    assert (by["cloud.pem"]["parse_status"], by["cloud.pem"]["detail"]) == ("skipped", "cloud_placeholder")
    assert by["cloud.pem"]["evidence_confidence"] == "low" and by["local.pem"]["parse_status"] == "ok"
    assert opened == ["local.pem"]
    assert summary["skipped"]["cloud_placeholder"] == 1 and summary["files_read"] == 1


@windows_only
def test_placeholders_with_other_extensions_are_ignored_entirely(tmp_path):
    doc = put(tmp_path, "report.docx", b"x")
    pfx = put(tmp_path, "cloud.pfx", b"x")
    with offline_attribute(doc), offline_attribute(pfx):
        records, summary = run_scan(tmp_path)
    assert [(r["filename"], r["detail"]) for r in records] == [("cloud.pfx", "cloud_placeholder")]
    assert summary["candidate_files"] == 1 and summary["skipped"] == {"cloud_placeholder": 1}


# ---------------------------------------------------------------- more adversarial and partial-scan cases
def test_many_failing_files_keep_every_record_but_cap_the_error_list(tmp_path, monkeypatch):
    for i in range(1100):
        (tmp_path / f"f{i:04d}.pem").write_bytes(PEM)
    fail_open(monkeypatch, lambda p: p.endswith(".pem"), lambda p: PermissionError(13, "denied", p, 5))
    records, summary = run_scan(tmp_path)
    assert len(records) == 1100 and {r["parse_status"] for r in records} == {"access_denied"}
    assert summary["errors_total"] == 1100 and len(summary["errors"]) == 1000     # list capped, nothing lost
    assert summary["records_by_status"] == {"access_denied": 1100} and summary["complete"]


def test_a_failing_stat_on_one_entry_is_isolated(tmp_path, monkeypatch):
    put(tmp_path, "bad.pem", PEM)
    put(tmp_path, "good.pem", PEM)

    class Entry:
        def __init__(self, real):
            self._real, self.name, self.path = real, real.name, real.path

        def stat(self, follow_symlinks=True):
            if self.name == "bad.pem":
                raise PermissionError(13, "denied", self.path, 5)
            return self._real.stat(follow_symlinks=follow_symlinks)

        def is_symlink(self):
            return self._real.is_symlink()

    class Listing:
        def __init__(self, entries):
            self._entries = entries

        def __enter__(self):
            return iter(self._entries)

        def __exit__(self, *exc):
            return False

    real_scandir = os.scandir

    def fake(path, *a, **k):
        with real_scandir(path, *a, **k) as it:
            return Listing([Entry(e) for e in it])
    monkeypatch.setattr(os, "scandir", fake)
    records, summary = run_scan(tmp_path)
    assert names(records) == ["good.pem"]
    assert summary["errors"] == [{"path": str(tmp_path / "bad.pem"), "kind": "stat",
                                  "code": "PermissionError:WinError 5"}]
    assert summary["complete"] is True


@windows_only
def test_paths_longer_than_max_path_never_crash_the_scan(tmp_path):
    parts = ["d" * 60] * 5                                              # ~300 characters in total
    deep = "\\\\?\\" + os.path.join(str(tmp_path), *parts)
    os.makedirs(deep)
    with open(deep + "\\c.pem", "wb") as fh:
        fh.write(PEM)
    put(tmp_path, "shallow.pem", PEM)
    records, summary = run_scan(tmp_path)
    # Whether the deep file is reachable depends on this machine's LongPathsEnabled setting. Either
    # way the scan must finish, report the shallow file, and never lose track of a failure.
    assert "shallow.pem" in names(records) and summary["stop_reason"] == "completed"
    if "c.pem" not in names(records):
        assert summary["errors_total"] >= 1, "an unreachable deep path must be reported, not silently dropped"
    assert all(r["parse_status"] in ("ok", "access_denied", "read_error") for r in records)


@windows_only
def test_a_real_acl_denial_is_reported_as_access_denied(tmp_path):
    import subprocess
    denied = put(tmp_path, "denied.pem", PEM)
    put(tmp_path, "fine.pem", PEM)
    user = os.environ.get("USERNAME", "")
    if subprocess.run(["icacls", str(denied), "/deny", f"{user}:(R)"], capture_output=True).returncode != 0:
        pytest.skip("could not set a deny ACE on this machine")
    try:
        try:
            open(denied, "rb").close()
            pytest.skip("deny ACE is not enforced for this account (elevated/backup rights)")
        except PermissionError:
            pass
        records, summary = run_scan(tmp_path)
    finally:
        subprocess.run(["icacls", str(denied), "/remove:d", user], capture_output=True)
    by = {r["filename"]: r for r in records}
    assert (by["denied.pem"]["parse_status"], by["denied.pem"]["access_error"]) == (
        "access_denied", "PermissionError:errno 13")
    assert by["fine.pem"]["parse_status"] == "ok" and summary["complete"]


@windows_only
def test_hidden_and_system_files_are_still_scanned(tmp_path):
    from treegen import file_attributes
    hidden = put(tmp_path, "hidden.pem", PEM)
    with file_attributes(hidden, 0x2 | 0x4):                          # HIDDEN | SYSTEM
        records, _ = run_scan(tmp_path)
    assert names(records) == ["hidden.pem"] and records[0]["parse_status"] == "ok"


@windows_only
def test_a_dangling_junction_root_is_reported_not_found(tmp_path):
    target, link = tmp_path / "target", tmp_path / "link"
    target.mkdir()
    assert make_junction(link, target)
    os.rmdir(target)
    try:
        records, summary = run_scan(link)
    finally:
        os.rmdir(link)
    assert records == [] and summary["roots"][0]["status"] == "not_found"
    assert summary["errors"][0]["kind"] == "root"


def test_complete_means_no_limit_was_hit_not_that_nothing_went_wrong(tmp_path, monkeypatch):
    # Pinned semantics: `complete` is about limits/cancellation only. Callers (the run status
    # logic) must also look at errors_total and the per-root status to decide completed vs partial.
    put(tmp_path, "locked/a.pem", PEM)
    put(tmp_path, "ok/b.pem", PEM)
    fail_scandir(monkeypatch, lambda p: p.endswith("locked"), lambda p: PermissionError(13, "x", p, 5))
    _, summary = run_scan(tmp_path, tmp_path / "missing")
    assert summary["complete"] is True and summary["stop_reason"] == "completed"
    assert summary["errors_total"] == 2
    assert [r["status"] for r in summary["roots"]] == ["scanned", "not_found"]
