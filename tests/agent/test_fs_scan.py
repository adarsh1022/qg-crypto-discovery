"""Scan: discovery, ordering, records, duplicates, limits, exclusions, robustness."""
import builtins
import hashlib
import json
import os
import random
import time
import warnings

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.serialization import pkcs12

import certgen
import pemgen
from agent.fs_scan import Scan, _read_limited
from agent.observations import ALL_STATUSES, RECORD_FIELDS
from agent.scan_config import ScanConfig
from treegen import NOW, StepClock, put, run_scan

P256 = pemgen.der_of("key_p256")
RSA = pemgen.der_of("key_rsa2048")
ED = pemgen.der_of("key_ed25519")
PEM_P256 = pemgen.pem_encode(P256)
FP = {d: hashlib.sha256(d).hexdigest() for d in (P256, RSA, ED)}


@pytest.fixture
def open_spy(monkeypatch):
    """Record every builtins.open call made while it is installed (path, mode)."""
    calls = []
    real = builtins.open

    def spy(file, mode="r", *a, **k):
        calls.append((os.fspath(file), mode))
        return real(file, mode, *a, **k)
    monkeypatch.setattr(builtins, "open", spy)
    return calls


def names(records):
    return [r["filename"] for r in records]


# ---------------------------------------------------------------- discovery
def test_finds_every_candidate_extension_case_insensitively(tmp_path, open_spy):
    put(tmp_path, "a.pem", PEM_P256)
    put(tmp_path, "B.CRT", pemgen.pem_encode(RSA))
    put(tmp_path, "c.Der", ED)
    put(tmp_path, "d.cer", P256)
    put(tmp_path, "e.cert", PEM_P256)
    for ignored in ("f.txt", "g.key", "h", "i.pem.bak", "j.pemx", "k.crt.old"):
        put(tmp_path, ignored, PEM_P256)                  # certificate content, wrong extension
    open_spy.clear()
    records, summary = run_scan(tmp_path)
    assert sorted(names(records)) == ["B.CRT", "a.pem", "c.Der", "d.cer", "e.cert"]
    assert all(r["parse_status"] == "ok" for r in records)
    assert summary["candidate_files"] == 5 and summary["files_read"] == 5
    assert sorted(os.path.basename(p) for p, _ in open_spy) == sorted(names(records))   # nothing else opened
    assert all(mode == "rb" for _, mode in open_spy)


def test_order_is_deterministic_and_files_come_before_subdirectories(tmp_path):
    put(tmp_path, "b.pem", PEM_P256)
    put(tmp_path, "a.pem", PEM_P256)
    put(tmp_path, "z/c.pem", PEM_P256)
    put(tmp_path, "A/d.pem", PEM_P256)
    put(tmp_path, "m/n/e.pem", PEM_P256)
    first, _ = run_scan(tmp_path)
    second, _ = run_scan(tmp_path)
    assert names(first) == ["a.pem", "b.pem", "d.pem", "e.pem", "c.pem"]
    assert first == second


def test_paths_scan_root_and_filename(tmp_path):
    put(tmp_path, "sub dir/ü-certificate 1.pem", PEM_P256)
    (rec,), _ = run_scan(tmp_path)
    assert rec["filename"] == "ü-certificate 1.pem"
    assert rec["path"] == str(tmp_path / "sub dir" / "ü-certificate 1.pem")
    assert rec["scan_root"] == os.path.normpath(str(tmp_path))
    assert rec["discovered_at"] == "2025-06-01T12:00:00Z"


def test_every_record_matches_the_schema_and_is_json(tmp_path):
    put(tmp_path, "ok.pem", PEM_P256)
    put(tmp_path, "bad.pem", b"-----BEGIN CERTIFICATE-----\nAAAA\n")
    put(tmp_path, "none.crt", b"")
    put(tmp_path, "x.pfx", b"whatever")
    records, summary = run_scan(tmp_path)
    for rec in records:
        assert tuple(rec) == RECORD_FIELDS and rec["parse_status"] in ALL_STATUSES
        json.dumps(rec)
    json.dumps(summary)


def test_a_directory_named_like_a_certificate_is_traversed_not_read(tmp_path, open_spy):
    put(tmp_path, "weird.pem/inner.crt", PEM_P256)
    open_spy.clear()
    records, summary = run_scan(tmp_path)
    assert names(records) == ["inner.crt"] and summary["candidate_files"] == 1
    assert [os.path.basename(p) for p, _ in open_spy] == ["inner.crt"]


def test_a_dotfile_named_exactly_like_an_extension_is_not_a_candidate(tmp_path, open_spy):
    # Python's splitext() treats ".pem" as a name with no extension. Documented limitation.
    put(tmp_path, ".pem", PEM_P256)
    put(tmp_path, ".crt", PEM_P256)
    put(tmp_path, ".hidden.pem", PEM_P256)                  # a real extension: still found
    open_spy.clear()
    records, summary = run_scan(tmp_path)
    assert names(records) == [".hidden.pem"] and summary["candidate_files"] == 1
    assert [os.path.basename(p) for p, _ in open_spy] == [".hidden.pem"]


def test_bundle_yields_one_record_per_certificate_with_positions(tmp_path):
    put(tmp_path, "bundle.pem", PEM_P256 + pemgen.pem_encode(RSA) + pemgen.pem_encode(ED))
    records, summary = run_scan(tmp_path)
    assert [(r["chain_index"], r["chain_total"], r["sha256"]) for r in records] == [
        (0, 3, FP[P256]), (1, 3, FP[RSA]), (2, 3, FP[ED])]
    assert summary["records"] == 3 and summary["unique_certificates"] == 3


def test_unparseable_files_each_get_a_record_with_a_status(tmp_path):
    put(tmp_path, "corrupt.pem", b"-----BEGIN CERTIFICATE-----\nAAA*\n-----END CERTIFICATE-----\n")
    put(tmp_path, "empty.crt", b"")
    put(tmp_path, "keyonly.pem", pemgen.pem_encode(b"x", label=b"PRIVATE KEY"))
    put(tmp_path, "text.cer", b"hello world")
    put(tmp_path, "truncated.der", P256[:50])
    put(tmp_path, "good.pem", PEM_P256)
    records, summary = run_scan(tmp_path)
    got = {r["filename"]: (r["parse_status"], r["detail"]) for r in records}
    assert got["empty.crt"] == ("no_certificate", "empty_file")
    assert got["keyonly.pem"] == ("no_certificate", "no_certificate_block")
    assert got["text.cer"] == ("malformed", "unrecognized_content")
    assert got["corrupt.pem"][0] == "malformed" and got["truncated.der"][0] == "malformed"
    assert got["good.pem"] == ("ok", None)
    assert summary["records_by_status"] == {"ok": 1, "malformed": 3, "no_certificate": 2}


def test_misnamed_formats_flag_the_extension_mismatch(tmp_path):
    put(tmp_path, "der_named_pem.pem", P256)
    put(tmp_path, "pem_named_der.der", PEM_P256)
    put(tmp_path, "fine.crt", PEM_P256)
    records, _ = run_scan(tmp_path)
    flags = {r["filename"]: r["extension_mismatch"] for r in records}
    assert flags == {"der_named_pem.pem": True, "pem_named_der.der": True, "fine.crt": False}


def test_pkcs12_extensions_are_reported_without_being_opened(tmp_path, open_spy):
    cert = x509.load_der_x509_certificate(RSA)
    pfx = pkcs12.serialize_key_and_certificates(b"n", certgen.key("rsa2048"), cert, None, ser.NoEncryption())
    put(tmp_path, "server.pfx", pfx)
    put(tmp_path, "CLIENT.P12", pfx)
    open_spy.clear()
    records, summary = run_scan(tmp_path)
    assert [(r["filename"], r["format"], r["parse_status"], r["detail"]) for r in records] == [
        ("CLIENT.P12", "pkcs12", "unsupported", "pkcs12_not_read"),
        ("server.pfx", "pkcs12", "unsupported", "pkcs12_not_read")]
    assert open_spy == [] and summary["files_read"] == 0 and summary["candidate_files"] == 2


def test_pkcs12_content_under_a_certificate_extension_is_sniffed_not_parsed(tmp_path):
    cert = x509.load_der_x509_certificate(RSA)
    pfx = pkcs12.serialize_key_and_certificates(b"n", certgen.key("rsa2048"), cert, None, ser.NoEncryption())
    put(tmp_path, "sneaky.crt", pfx)
    (rec,), _ = run_scan(tmp_path)
    assert (rec["format"], rec["parse_status"], rec["detail"]) == ("pkcs12", "unsupported", "pkcs12_not_handled_yet")
    assert rec["sha256"] is None


def test_hidden_and_dot_directories_are_scanned(tmp_path):
    put(tmp_path, ".hidden/secret dir/c.pem", PEM_P256)
    assert names(run_scan(tmp_path)[0]) == ["c.pem"]


def test_nothing_found_is_a_clean_empty_scan(tmp_path):
    put(tmp_path, "readme.txt", b"nothing here")
    records, summary = run_scan(tmp_path)
    assert records == [] and summary["complete"] and summary["stop_reason"] == "completed"
    assert summary["roots"] == [{"root": os.path.normpath(str(tmp_path)), "status": "scanned"}]


# ---------------------------------------------------------------- duplicates keep every sighting
def test_duplicate_certificates_are_all_reported_and_marked(tmp_path):
    put(tmp_path, "a.pem", PEM_P256)
    put(tmp_path, "b.crt", P256)                        # same certificate, DER
    put(tmp_path, "sub/c.cer", PEM_P256)
    put(tmp_path, "other.pem", pemgen.pem_encode(RSA))
    records, summary = run_scan(tmp_path)
    assert names(records) == ["a.pem", "b.crt", "other.pem", "c.cer"]
    assert [r["duplicate_in_scan"] for r in records] == [False, True, False, True]
    assert [r["sha256"] for r in records] == [FP[P256], FP[P256], FP[RSA], FP[P256]]
    assert summary["records"] == 4 and summary["unique_certificates"] == 2
    assert summary["duplicate_observations"] == 2


def test_duplicates_inside_one_bundle_are_marked_too(tmp_path):
    put(tmp_path, "twice.pem", PEM_P256 + PEM_P256)
    records, summary = run_scan(tmp_path)
    assert [(r["chain_index"], r["duplicate_in_scan"]) for r in records] == [(0, False), (1, True)]
    assert summary["duplicate_observations"] == 1


def test_files_without_fingerprints_are_never_marked_duplicate(tmp_path):
    put(tmp_path, "a.pem", b"")
    put(tmp_path, "b.pem", b"")
    records, summary = run_scan(tmp_path)
    assert [r["duplicate_in_scan"] for r in records] == [False, False]
    assert summary["duplicate_observations"] == 0 and summary["unique_certificates"] == 0


# ---------------------------------------------------------------- roots
def test_multiple_roots_keep_their_own_scan_root(tmp_path):
    put(tmp_path, "one/a.pem", PEM_P256)
    put(tmp_path, "two/b.pem", pemgen.pem_encode(RSA))
    records, summary = run_scan(tmp_path / "one", tmp_path / "two")
    assert [(r["filename"], os.path.basename(r["scan_root"])) for r in records] == [("a.pem", "one"), ("b.pem", "two")]
    assert [r["status"] for r in summary["roots"]] == ["scanned", "scanned"]


def test_missing_root_and_file_root_do_not_stop_the_scan(tmp_path):
    put(tmp_path, "real/a.pem", PEM_P256)
    put(tmp_path, "file.txt", b"x")
    records, summary = run_scan(tmp_path / "missing", tmp_path / "file.txt", tmp_path / "real")
    assert names(records) == ["a.pem"]
    assert [r["status"] for r in summary["roots"]] == ["not_found", "not_a_directory", "scanned"]
    assert summary["errors_total"] == 1 and summary["errors"][0]["kind"] == "root"
    assert summary["complete"] is True


def test_overlapping_roots_never_duplicate_observations(tmp_path):
    put(tmp_path, "outer/inner/a.pem", PEM_P256)
    put(tmp_path, "outer/b.pem", PEM_P256)
    for roots in ((tmp_path / "outer", tmp_path / "outer" / "inner"),
                  (tmp_path / "outer" / "inner", tmp_path / "outer"),
                  (tmp_path / "outer", tmp_path / "outer")):
        records, summary = run_scan(*roots)
        assert sorted(names(records)) == ["a.pem", "b.pem"], roots
        assert summary["skipped"]["root_overlap"] == 1
        assert "overlap" in [r["status"] for r in summary["roots"]]


def test_a_root_inside_an_excluded_directory_is_still_scanned(tmp_path):
    put(tmp_path, "outer/node_modules/inner/a.pem", PEM_P256)
    records, summary = run_scan(tmp_path / "outer", tmp_path / "outer" / "node_modules" / "inner")
    assert names(records) == ["a.pem"]
    assert [r["status"] for r in summary["roots"]] == ["scanned", "scanned"]
    assert summary["skipped"].get("excluded_dir") == 1


# ---------------------------------------------------------------- exclusions
def test_default_exclusions_are_pruned_at_any_depth_case_insensitively(tmp_path):
    # (the filesystem is case-insensitive, so each spelling below is a distinct directory)
    for d in ("Node_Modules", ".GIT", "$RECYCLE.BIN", "winsxs", "a/b/NODE_MODULES/c"):
        put(tmp_path, f"{d}/hidden.pem", PEM_P256)
    put(tmp_path, "keep/keep.pem", PEM_P256)
    records, summary = run_scan(tmp_path)
    assert names(records) == ["keep.pem"]
    assert summary["skipped"]["excluded_dir"] == 5


def test_excluded_directories_are_never_listed(tmp_path, monkeypatch):
    put(tmp_path, "node_modules/x.pem", PEM_P256)
    put(tmp_path, "skipme/y.pem", PEM_P256)
    put(tmp_path, "ok/z.pem", PEM_P256)
    listed = []
    real = os.scandir
    monkeypatch.setattr(os, "scandir", lambda p, *a, **k: (listed.append(os.path.basename(str(p))), real(p, *a, **k))[1])
    records, _ = run_scan(tmp_path, exclude_paths=(str(tmp_path / "skipme"),))
    assert names(records) == ["z.pem"]
    assert "node_modules" not in listed and "skipme" not in listed and "ok" in listed


def test_exclusion_list_is_replaceable(tmp_path):
    put(tmp_path, "node_modules/x.pem", PEM_P256)
    put(tmp_path, "custom/y.pem", PEM_P256)
    assert names(run_scan(tmp_path, exclude_dir_names=("custom",))[0]) == ["x.pem"]
    assert sorted(names(run_scan(tmp_path, exclude_dir_names=("unrelated",))[0])) == ["x.pem", "y.pem"]


def test_a_root_whose_own_name_is_excluded_is_still_scanned(tmp_path):
    put(tmp_path, "node_modules/x.pem", PEM_P256)
    assert names(run_scan(tmp_path / "node_modules")[0]) == ["x.pem"]


def test_extension_list_is_configurable(tmp_path):
    put(tmp_path, "a.pem", PEM_P256)
    put(tmp_path, "b.custom", PEM_P256)
    assert names(run_scan(tmp_path, extensions=("custom",))[0]) == ["b.custom"]


# ---------------------------------------------------------------- limits
def test_depth_limit(tmp_path):
    put(tmp_path, "a/b/c/d/deep.pem", PEM_P256)
    records, summary = run_scan(tmp_path, max_depth=3)
    assert records == [] and summary["skipped"]["depth_limit"] == 1 and summary["complete"]
    assert names(run_scan(tmp_path, max_depth=4)[0]) == ["deep.pem"]
    put(tmp_path, "top.pem", PEM_P256)
    assert names(run_scan(tmp_path, max_depth=0)[0]) == ["top.pem"]


def test_entry_limit_stops_the_scan_and_keeps_partial_results(tmp_path):
    for i in range(30):
        put(tmp_path, f"f{i:02d}.pem", PEM_P256)
    records, summary = run_scan(tmp_path, max_entries=10)
    assert summary["stop_reason"] == "entry_limit" and summary["complete"] is False
    assert 0 < len(records) < 30 and summary["roots"][0]["status"] == "partial"


def test_candidate_limit(tmp_path):
    for i in range(20):
        put(tmp_path, f"f{i:02d}.pem", PEM_P256)
    records, summary = run_scan(tmp_path, max_candidates=5)
    assert len(records) == 5 and summary["stop_reason"] == "candidate_limit" and not summary["complete"]
    records, summary = run_scan(tmp_path, max_candidates=20)                 # exactly enough: still complete
    assert len(records) == 20 and summary["complete"]


def test_time_budget_with_a_fake_clock(tmp_path):
    for i in range(50):
        put(tmp_path, f"f{i:02d}.pem", PEM_P256)
    records, summary = run_scan(tmp_path, clock=StepClock(1.0), time_budget_seconds=10)
    assert summary["stop_reason"] == "time_limit" and not summary["complete"]
    assert 0 < len(records) < 50


def test_cancel_hook(tmp_path):
    for i in range(30):
        put(tmp_path, f"f{i:02d}.pem", PEM_P256)
    ticks = iter(range(10_000))
    records, summary = run_scan(tmp_path, should_stop=lambda: next(ticks) >= 8)
    assert summary["stop_reason"] == "cancelled" and 0 < len(records) < 30


def test_remaining_roots_are_marked_not_reached(tmp_path):
    put(tmp_path, "one/a.pem", PEM_P256)
    put(tmp_path, "two/b.pem", PEM_P256)
    put(tmp_path, "three/c.pem", PEM_P256)
    records, summary = run_scan(tmp_path / "one", tmp_path / "two", tmp_path / "three", max_candidates=1)
    assert names(records) == ["a.pem"]
    # root one has exactly one candidate (within the limit); root two hits the limit; root three is never reached
    assert [r["status"] for r in summary["roots"]] == ["scanned", "partial", "not_reached"]
    assert summary["stop_reason"] == "candidate_limit"


def test_oversized_files_are_reported_without_being_read(tmp_path, open_spy):
    put(tmp_path, "big.pem", PEM_P256 + b"#" * 5000)
    put(tmp_path, "small.pem", PEM_P256)
    open_spy.clear()
    records, summary = run_scan(tmp_path, max_file_bytes=2000)
    got = {r["filename"]: (r["parse_status"], r["detail"]) for r in records}
    assert got == {"big.pem": ("too_large", "file_too_large"), "small.pem": ("ok", None)}
    assert [os.path.basename(p) for p, _ in open_spy] == ["small.pem"]


def test_read_limited_detects_files_that_grew_past_the_cap(tmp_path):
    p = put(tmp_path, "g.pem", b"x" * 100)
    assert _read_limited(str(p), 100) == b"x" * 100
    assert _read_limited(str(p), 99) is None


def test_max_certs_per_file(tmp_path):
    put(tmp_path, "big.pem", PEM_P256 * 5)
    records, summary = run_scan(tmp_path, max_certs_per_file=3)
    assert len(records) == 3 and summary["bundles_truncated"] == 1


# ---------------------------------------------------------------- unpaired surrogates in file names
def test_surrogate_filenames_produce_strictly_utf8_safe_output(tmp_path, monkeypatch):
    # Windows allows file names with unpaired UTF-16 surrogates; Python keeps them as lone
    # surrogate code points, which strict UTF-8 cannot encode. Emitted metadata must be safe.
    with pytest.raises(UnicodeEncodeError):
        "bad\ud800name.pem".encode("utf-8")                    # control: the raw name really is unsafe
    root = tmp_path / "root\udc80dir"
    put(root, "bad\ud800name.pem", PEM_P256)
    put(root, "sub\ud801dir/x\udfffy.der", P256)
    put(root, "plain.pem", PEM_P256)
    put(root, "😀 emoji.pem", PEM_P256)                         # a VALID non-BMP character must be left alone
    put(root, "locked\ud802dir/hidden.pem", PEM_P256)
    real = os.scandir

    def fake(path, *a, **k):
        if os.fspath(path).endswith("locked\ud802dir"):
            raise PermissionError(13, "denied", path, 5)
        return real(path, *a, **k)
    monkeypatch.setattr(os, "scandir", fake)

    records, summary = run_scan(root)                          # the scan itself must complete
    assert summary["stop_reason"] == "completed" and summary["complete"]
    expected_files = {"bad\\ud800name.pem", "x\\udfffy.der", "plain.pem", "😀 emoji.pem"}
    assert {r["filename"] for r in records} == expected_files
    assert all(r["parse_status"] == "ok" for r in records)     # the RAW path was used to open each file
    assert {r["sha256"] for r in records} == {FP[P256]}

    blob = json.dumps({"records": records, "summary": summary}, ensure_ascii=False).encode("utf-8")
    assert blob                                                # strict UTF-8 JSON/NDJSON-safe
    clean_root = str(root).replace("\udc80", "\\udc80")
    for rec in records:
        for field in ("path", "filename", "scan_root"):
            rec[field].encode("utf-8")
            assert not any(0xD800 <= ord(ch) <= 0xDFFF for ch in rec[field]), field
        assert rec["scan_root"] == clean_root and rec["path"].startswith(clean_root)
    by_name = {r["filename"]: r["path"] for r in records}
    assert by_name["x\\udfffy.der"] == str(root / "sub\ud801dir" / "x\udfffy.der").replace(
        "\udc80", "\\udc80").replace("\ud801", "\\ud801").replace("\udfff", "\\udfff")

    assert summary["roots"] == [{"root": clean_root, "status": "scanned"}]
    (error,) = summary["errors"]                               # the unreadable surrogate-named directory
    assert error["kind"] == "listdir" and error["code"] == "PermissionError:WinError 5"
    assert error["path"] == str(root / "locked\ud802dir").replace("\udc80", "\\udc80").replace("\ud802", "\\ud802")
    error["path"].encode("utf-8")


def test_a_scan_can_be_consumed_once(tmp_path):
    scan = Scan(ScanConfig(roots=(str(tmp_path),)))
    list(scan.records())
    with pytest.raises(RuntimeError):
        list(scan.records())


def test_abandoning_a_scan_early_reports_cancelled(tmp_path):
    for i in range(5):
        put(tmp_path, f"f{i}.pem", PEM_P256)
    scan = Scan(ScanConfig(roots=(str(tmp_path),)), now=lambda: NOW)
    gen = scan.records()
    next(gen)
    gen.close()
    assert scan.summary["stop_reason"] == "cancelled" and scan.summary["complete"] is False


def test_summary_counters_are_consistent(tmp_path):
    put(tmp_path, "a.pem", PEM_P256 + pemgen.pem_encode(RSA))
    put(tmp_path, "sub/b.der", ED)
    put(tmp_path, "sub/c.crt", b"")
    put(tmp_path, "sub/d.txt", b"ignored")
    records, s = run_scan(tmp_path)
    assert s["records"] == len(records) == sum(s["records_by_status"].values()) == 4
    assert s["directories_visited"] == 2 and s["entries_visited"] == 5
    assert s["candidate_files"] == 3 and s["files_read"] == 3 and s["elapsed_seconds"] >= 0


# ---------------------------------------------------------------- oracle agreement
def test_generated_tree_agrees_with_cryptography(tmp_path):
    ders = [certgen.CASES[n][0]() for n in ("key_p256", "key_rsa2048", "key_ed25519", "san_many_200",
                                            "name_many_attributes", "bc_ca_pathlen3", "sig_rsa_pss_sha256")]
    for i, der in enumerate(ders):
        put(tmp_path, f"d{i % 3}/c{i}.pem" if i % 2 else f"d{i % 3}/c{i}.der",
            pemgen.pem_encode(der) if i % 2 else der)
    records, _ = run_scan(tmp_path)
    expected = sorted(x509.load_der_x509_certificate(d).fingerprint(hashes.SHA256()).hex() for d in ders)
    assert sorted(r["sha256"] for r in records) == expected


def test_real_world_bundle_from_the_pip_vendored_certifi(tmp_path):
    from pip._vendor import certifi
    bundle = certifi.where()
    with open(bundle, "rb") as fh:
        data = fh.read()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        expected = [c.fingerprint(hashes.SHA256()).hex() for c in x509.load_pem_x509_certificates(data)]
    records, summary = run_scan(os.path.dirname(bundle), extensions=("pem",))
    assert len(expected) >= 100
    assert [r["sha256"] for r in records] == expected
    assert all(r["parse_status"] == "ok" for r in records) and summary["complete"]


# ---------------------------------------------------------------- robustness
def test_randomised_trees_never_break_the_scanner(tmp_path):
    rnd = random.Random(2024)
    key_pem = pemgen.private_key_pems()["pkcs8_ec"]
    blobs = [PEM_P256, P256, key_pem + PEM_P256, PEM_P256[: len(PEM_P256) // 2], b"", bytes(range(256)),
             b"-----BEGIN CERTIFICATE-----\n" * 3, pemgen.pem_encode(b"x" * 50), key_pem, PEM_P256 * 3]
    exts = [".pem", ".crt", ".cer", ".der", ".cert", ".PEM", ".txt", ".key", "", ".pfx", ".p12", ".bak"]
    expected_candidates = 0
    for i in range(300):
        depth = rnd.randrange(0, 5)
        rel = "/".join(f"d{rnd.randrange(4)}" for _ in range(depth)) + f"/f{i}{rnd.choice(exts)}"
        ext = os.path.splitext(rel)[1].lower()
        put(tmp_path, rel.lstrip("/"), rnd.choice(blobs))
        expected_candidates += ext in (".pem", ".crt", ".cer", ".der", ".cert", ".pfx", ".p12")
    records, summary = run_scan(tmp_path)
    assert summary["complete"] and summary["candidate_files"] == expected_candidates
    assert summary["records"] == len(records) == sum(summary["records_by_status"].values())
    for rec in records:
        assert tuple(rec) == RECORD_FIELDS and rec["parse_status"] in ALL_STATUSES
        assert (rec["sha256"] is not None) == (rec["parse_status"] == "ok")
        assert rec["detail"] != "internal_error"
        assert os.path.splitext(rec["filename"])[1].lower() in (".pem", ".crt", ".cer", ".der", ".cert", ".pfx", ".p12")


def test_performance_on_a_few_thousand_files(tmp_path):
    for d in range(100):
        base = tmp_path / f"dir{d}"
        base.mkdir()
        for f in range(30):
            (base / f"file{f}.txt").write_bytes(b"x")
        (base / "c.pem").write_bytes(PEM_P256)
    start = time.perf_counter()
    records, summary = run_scan(tmp_path)
    elapsed = time.perf_counter() - start
    assert len(records) == 100 and summary["entries_visited"] == 3100 + 100
    assert elapsed < 10, f"{summary['entries_visited']} entries took {elapsed:.1f}s"
