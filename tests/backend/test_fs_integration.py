"""End to end: the real Phase 1 scanner -> backend ingestion -> SQLite, including key-safety checks on the database file."""
import base64
import os

import pytest

import pemgen
import pfxgen
from backend import db, fs_ingest, fs_queries, runs
from ingestfx import NOW, at
from treegen import exclusive_lock, put, run_scan

ROOT, INTER, LEAF = pfxgen.chain()
fp = pfxgen.fp


def scan_into(conn, scan_root, *, config=None):
    """Scan a directory with the real agent and persist everything through the backend."""
    records, summary = run_scan(scan_root, **(config or {}))
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW, config={"roots": [str(scan_root)]})
    runs.start_run(conn, run_id, now=at(1))
    result = fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(9), summary=summary)
    return run_id, records, summary, result, final


def build_tree(tmp_path, with_keys=True):
    leaf_pem = pemgen.pem_encode(LEAF)
    keys = pemgen.private_key_pems()
    put(tmp_path, "app/server.pem", leaf_pem + (keys["pkcs8_rsa"] if with_keys else b""))
    put(tmp_path, "backup/server.crt", LEAF)                                       # the same certificate, as DER
    put(tmp_path, "chains/bundle.pem", pemgen.pem_encode(LEAF) + pemgen.pem_encode(INTER) + pemgen.pem_encode(ROOT))
    put(tmp_path, "store/dup.pfx", pfxgen.plain_with_key(extra_ca=(INTER, INTER, ROOT)) if with_keys
        else pfxgen.plain_certs_only((LEAF, INTER, INTER, ROOT)))
    if with_keys:
        for name, pem in keys.items():
            put(tmp_path, f"keys/{name}.pem", pem)                                 # key-only files
    put(tmp_path, "unicode/证书/😀.pem", pemgen.pem_encode(ROOT))
    return tmp_path


# ------------------------------------------------------------------ the whole pipeline
def test_real_scan_persists_identities_and_every_sighting(conn, tmp_path):
    run_id, records, summary, result, final = scan_into(conn, build_tree(tmp_path))
    assert result.rejected == () and result.accepted == len(records) == final.record_count
    counts = fs_queries.fs_counts(conn, run_id)

    leaf, inter, root = fp(LEAF), fp(INTER), fp(ROOT)
    by_sha = {}
    for o in fs_queries.list_fs_observations(conn, run_id, parse_status="ok"):
        by_sha.setdefault(o["sha256"], []).append(o)
    assert set(by_sha) == {leaf, inter, root}                                      # three identities ...
    assert {sha: len(v) for sha, v in by_sha.items()} == {leaf: 4, inter: 3, root: 3}      # ... ten sightings
    assert counts.sightings == 10 and counts.unique_certificates == 3 and counts.duplicate_observations == 7
    assert final.finding_count == 10 and conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 3
    assert fs_queries.get_certificate(conn, leaf)["sightings"] == 4

    pfx = [o for o in fs_queries.list_fs_observations(conn, run_id) if o["filename"] == "dup.pfx"]
    assert len(pfx) == 4 and sorted(o["sha256"] for o in pfx) == sorted([leaf, inter, inter, root])
    assert [o["entry_ordinal"] for o in pfx] == [0, 1, 2, 3] and all(o["chain_index"] is None for o in pfx)
    assert counts.repeats_within_file == 1 and all(o["format"] == "pkcs12" and o["chain_total"] == 4 for o in pfx)
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_key_only_files_become_no_certificate_observations_with_nothing_key_related(conn, tmp_path):
    run_id, *_ = scan_into(conn, build_tree(tmp_path))
    key_files = [o for o in fs_queries.list_fs_observations(conn, run_id) if o["path"].startswith(str(tmp_path / "keys"))]
    assert len(key_files) == len(pemgen.private_key_pems())
    assert {(o["parse_status"], o["sha256"], o["evidence_confidence"]) for o in key_files} == {("no_certificate", None, "low")}


def test_clean_real_scan_is_completed_with_derived_duration(conn, tmp_path):
    run_id, records, summary, result, final = scan_into(conn, build_tree(tmp_path))
    assert not [r for r in records if r["parse_status"] in ("access_denied", "read_error")]
    assert final.status == "completed" and final.error_summary is None and final.error_count == 0
    assert final.duration_ms == 8000 and summary["stop_reason"] == "completed"


def test_locked_file_makes_a_real_run_partial(conn, tmp_path):
    build_tree(tmp_path)
    locked = put(tmp_path, "app/locked.pem", pemgen.pem_encode(LEAF))
    with exclusive_lock(locked):                                                   # a real sharing violation
        run_id, records, summary, result, final = scan_into(conn, tmp_path)
    [bad] = [o for o in fs_queries.list_fs_observations(conn, run_id) if o["filename"] == "locked.pem"]
    assert (bad["parse_status"], bad["sha256"], bad["evidence_confidence"]) == ("access_denied", None, "low")
    assert bad["access_error"].startswith("PermissionError:")
    assert summary["complete"] is True                                             # the agent calls this a normal end ...
    assert final.status == "partial" and final.error_summary == "file_errors:1"    # ... the stored evidence says otherwise
    assert (final.error_count, final.finding_count) == (1, 10)


def test_scan_limit_makes_a_real_run_partial(conn, tmp_path):
    for i in range(5):
        put(tmp_path, f"c{i}.pem", pemgen.pem_encode(LEAF))
    run_id, records, summary, result, final = scan_into(conn, tmp_path, config=dict(max_candidates=2))
    assert summary["stop_reason"] == "candidate_limit" and summary["complete"] is False
    assert final.status == "partial" and final.stop_reason == "candidate_limit" and final.record_count == 2


def test_unreachable_root_is_a_real_coverage_gap(conn, tmp_path):
    put(tmp_path, "a.pem", pemgen.pem_encode(LEAF))
    missing = tmp_path / "does-not-exist"
    records, summary = run_scan(tmp_path, missing)
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=summary)
    assert final.status == "partial" and final.error_summary == "roots_not_scanned:1, file_errors:1"


def test_overlapping_real_roots_are_not_a_gap_and_nothing_is_stored_twice(conn, tmp_path):
    put(tmp_path, "sub/a.pem", pemgen.pem_encode(LEAF))
    records, summary = run_scan(tmp_path, tmp_path / "sub")
    run_id = runs.create_run(conn, "filesystem", "manual", now=NOW)
    runs.start_run(conn, run_id, now=at(1))
    fs_ingest.ingest_fs_batch(conn, run_id, fs_ingest.number_records(records), now=at(2))
    final = fs_ingest.finalize_fs_run(conn, run_id, now=at(3), summary=summary)
    assert [r["status"] for r in summary["roots"]] == ["scanned", "overlap"]
    assert final.status == "completed" and final.record_count == 1


def test_second_scan_of_the_same_tree_is_a_second_run_with_the_same_identities(conn, tmp_path):
    build_tree(tmp_path)
    first, *_ = scan_into(conn, tmp_path)
    second, *_ = scan_into(conn, tmp_path)
    one, two = fs_queries.fs_counts(conn, first), fs_queries.fs_counts(conn, second)
    assert (one.sightings, one.unique_certificates) == (two.sightings, two.unique_certificates) == (10, 3)
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == one.observations + two.observations
    cert = fs_queries.get_certificate(conn, fp(LEAF))
    assert [r["run_id"] for r in cert["runs"]] == [first, second] and cert["sightings"] == 8


def test_unicode_paths_round_trip(conn, tmp_path):
    run_id, *_ = scan_into(conn, build_tree(tmp_path))
    paths = [o["path"] for o in fs_queries.list_fs_observations(conn, run_id, sha256=fp(ROOT))]
    assert any(p.endswith("证书\\😀.pem") for p in paths)


# ------------------------------------------------------------------ 16. no raw material in the database
def database_bytes(path):
    out = b""
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(str(path) + suffix):
            with open(str(path) + suffix, "rb") as handle:
                out += handle.read()
    return out


def windows(data: bytes, size: int, step: int):
    return {data[i:i + size] for i in range(0, max(len(data) - size + 1, 1), step)}


def forbidden_material() -> list[bytes]:
    """Byte patterns that must never appear in the database: private keys, certificates and containers, in several encodings."""
    keys = pemgen.private_key_pems()
    out = list(windows(pfxgen.private_key_der(), 40, 3))
    for pem in keys.values():
        body = pemgen.key_body_text(pem)
        out += [w.encode() for w in pemgen.canary_windows(body, 40, 5)]
        try:
            out += list(windows(base64.b64decode(body), 40, 5))
        except Exception:                                                          # noqa: BLE001 - encrypted/openssh bodies
            pass
    for key in pemgen._keys().values():
        out += [c for c in pemgen.private_components(key) if len(c) >= 16]
    for der in (LEAF, INTER, ROOT):
        out += list(windows(der, 40, 5))
        out += [w.encode() for w in pemgen.canary_windows(base64.b64encode(der).decode(), 40, 7)]
        out += [w.encode() for w in pemgen.canary_windows(der.hex(), 40, 7)]
    out += list(windows(pfxgen.plain_with_key(extra_ca=(INTER, INTER, ROOT)), 40, 11))
    return out


def find_leaks(path) -> list[bytes]:
    raw = database_bytes(path)
    return [w for w in forbidden_material() if w in raw]


def test_no_key_certificate_or_container_bytes_reach_the_database_file(tmp_path):
    tree = build_tree(tmp_path / "tree")
    path = tmp_path / "evidence.db"
    conn = db.open_database(path)
    try:
        run_id, *_ = scan_into(conn, tree)
        assert fs_queries.fs_counts(conn, run_id).sightings == 10
        text_dump = "\n".join(conn.iterdump())
        before_checkpoint = find_leaks(path)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        after_checkpoint = find_leaks(path)
        raw = database_bytes(path)
    finally:
        conn.close()
    assert len(raw) > 4096
    assert before_checkpoint == [] and after_checkpoint == []
    assert "-----BEGIN" not in text_dump and "-----END" not in text_dump and "PRIVATE KEY" not in text_dump
    assert fp(LEAF).encode() in raw and b"CN=leaf" in raw                          # the check can see what IS stored


@pytest.mark.parametrize("plant", [
    lambda: base64.b64encode(LEAF).decode(),                                       # certificate DER, base64
    lambda: LEAF.hex(),                                                            # certificate DER, hex
    lambda: pemgen.key_body_text(pemgen.private_key_pems()["pkcs8_rsa"]),          # private key PEM body
    lambda: base64.b64encode(pfxgen.plain_with_key()).decode(),                    # the PKCS#12 container
])
def test_the_leak_detector_catches_planted_material(tmp_path, plant):
    path = tmp_path / "planted.db"
    conn = db.open_database(path)
    try:
        with db.transaction(conn):
            conn.execute("INSERT INTO meta (key, value) VALUES ('oops', ?)", (plant(),))
    finally:
        conn.close()
    assert find_leaks(path) != []


def test_the_leak_detector_catches_planted_raw_bytes_in_a_blob_sized_text_value(tmp_path):
    path = tmp_path / "planted.db"
    conn = db.open_database(path)
    try:
        with db.transaction(conn):
            conn.execute("INSERT INTO meta (key, value) VALUES ('oops', ?)", (LEAF.decode("latin-1"),))
    finally:
        conn.close()
    assert find_leaks(path) != []


def test_database_equals_the_same_scan_without_any_key_material(tmp_path):
    def stored(subdir, with_keys):
        tree = build_tree(tmp_path / subdir, with_keys)
        conn = db.open_database(":memory:")
        try:
            run_id, *_ = scan_into(conn, tree)
            rows = []
            for o in fs_queries.list_fs_observations(conn, run_id):
                if o["path"].startswith(str(tree / "keys")):
                    continue
                o = dict(o)
                for field in ("path", "scan_root", "run_id", "id"):
                    o[field] = str(o[field]).replace(str(tree), "<root>")
                rows.append(o)
            certs = [dict(r) for r in conn.execute("SELECT * FROM certificates ORDER BY sha256")]
            for c in certs:
                c["first_seen_run"] = c["last_seen_run"] = "<run>"
            return rows, certs
        finally:
            conn.close()
    with_keys, without = stored("with", True), stored("without", False)
    assert with_keys[1] == without[1]
    keep = ("path", "filename", "format", "sha256", "chain_index", "chain_total", "parse_status", "evidence_confidence",
            "subject", "issuer", "key_size", "warnings")
    project = lambda rows: [{k: r[k] for k in keep} for r in rows]                # noqa: E731
    assert project(with_keys[0]) == project(without[0])


def test_every_stored_text_value_is_clean(conn, tmp_path):
    scan_into(conn, build_tree(tmp_path))
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").fetchall():
        for row in conn.execute(f"SELECT * FROM {table}"):
            for value in row:
                assert not isinstance(value, (bytes, bytearray, memoryview)), table
                if isinstance(value, str):
                    assert "-----BEGIN" not in value and "-----END" not in value, table
                    value.encode("utf-8")


def test_hostile_records_cannot_smuggle_material_even_through_a_real_run(conn):
    from ingestfx import ok_record, running_run, ingest
    run_id = running_run(conn)
    smuggled = []
    for field in ("der", "pem", "raw", "private_key", "privatekey", "key_material", "secret", "password"):
        record = ok_record(n=1)
        record[field] = base64.b64encode(LEAF).decode()
        smuggled.append(record)
    for field in ("subject", "issuer", "path", "filename", "scan_root", "key_algorithm"):
        record = ok_record(n=2)
        record[field] = pemgen.pem_encode(LEAF).decode()
        smuggled.append(record)
    smuggled.append(ok_record(n=3, subject=LEAF))                                  # raw bytes in a text field
    result = ingest(conn, run_id, smuggled)
    assert result.accepted == 0 and len(result.rejected) == len(smuggled)
    assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == 0
    codes = {c for _, c in result.rejected}
    assert codes == {"unknown_field", "pem_armor_in_subject", "pem_armor_in_issuer", "pem_armor_in_path",
                     "pem_armor_in_filename", "pem_armor_in_scan_root", "too_long_key_algorithm", "bad_subject"}


# ------------------------------------------------------------------ PKCS#12 integrity warning through the real bridge
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell bridge")
def test_os_decrypted_certificates_keep_their_integrity_warning_end_to_end(conn, tmp_path):
    try:
        native = pfxgen.windows_native("chain")
    except pfxgen.FixtureUnavailable as exc:
        pytest.skip(f"cannot create a Windows-native fixture here: {exc}")
    put(tmp_path, "store/windows.pfx", native)
    run_id, records, summary, result, final = scan_into(conn, tmp_path)
    got = fs_queries.list_fs_observations(conn, run_id)
    assert len(got) == 3 and all(o["format"] == "pkcs12" and o["chain_index"] is None for o in got)
    flagged = [o for o in got if "pkcs12_integrity_not_verified" in o["warnings"]]
    assert flagged and all(o["evidence_confidence"] == "medium" for o in flagged)
    assert {o["sha256"] for o in got} == {fp(LEAF), fp(INTER), fp(ROOT)}
    assert final.status == "completed"


def test_pfx_records_from_the_real_scanner_survive_backend_validation_unchanged(conn, tmp_path):
    put(tmp_path, "x.pfx", pfxgen.plain_with_key())
    run_id, records, *_ = scan_into(conn, tmp_path)
    got = fs_queries.list_fs_observations(conn, run_id)
    assert [(o["sha256"], o["chain_total"], o["chain_role"]) for o in got] == [
        (r["sha256"], r["chain_total"], r["chain_role"]) for r in records]
    assert [o["warnings"] for o in got] == [r["warnings"] for r in records]


def test_parsing_the_summary_does_not_modify_it(tmp_path):
    from backend.fs_record import parse_summary
    put(tmp_path, "a.pem", pemgen.pem_encode(LEAF))
    _, summary = run_scan(tmp_path)
    before = repr(summary)
    assert parse_summary(summary) is not None and repr(summary) == before
