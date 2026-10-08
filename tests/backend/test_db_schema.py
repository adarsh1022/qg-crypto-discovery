"""Schema contract: STRICT typing, no raw material, enums, constraints, indexes, graph rules."""
import re
import sqlite3

import pytest

from agent import observations
from backend import run_state
from dbfixtures import (SHA_A, SHA_B, T_MS, T_S, cert_row, edge_row, fs_failure_row, fs_row, insert, make_cert,
                        make_node, make_run, run_row, tls_row)


def table_names(conn):
    return [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def columns(conn):
    """(table, column, declared type) for every column of every table."""
    out = []
    for table in table_names(conn):
        for row in conn.execute(f"PRAGMA table_xinfo({table})"):
            out.append((table, row["name"], row["type"].upper()))
    return out


def check_values(conn, table, column):
    """The values in `column IN (...)` of the table's CREATE statement."""
    sql = conn.execute("SELECT sql FROM sqlite_master WHERE name = ?", (table,)).fetchone()[0]
    match = re.search(rf"\b{column}\s+IN\s*\(([^)]*)\)", sql)
    assert match, f"no IN-list for {table}.{column}"
    return set(re.findall(r"'([^']*)'", match.group(1)))


# ------------------------------------------------------------------ raw-material contract
RAW_TOKENS = {"raw", "der", "pem", "secret", "password"}
RAW_PHRASES = ("private_key", "privatekey", "key_material")


def is_raw_material_name(name: str) -> bool:
    """Names that would hold raw certificate/key material. key_algorithm / key_size / key_curve are fine."""
    lowered = name.lower()
    return bool(set(lowered.split("_")) & RAW_TOKENS) or any(p in lowered for p in RAW_PHRASES)


@pytest.mark.parametrize("name", ["raw", "raw_der", "cert_der", "der", "pem", "pem_text", "private_key", "privatekey",
                                  "key_material", "secret", "client_secret", "password", "password_hash", "RAW_DATA"])
def test_raw_material_detector_flags_dangerous_names(name):
    assert is_raw_material_name(name)


@pytest.mark.parametrize("name", ["key_algorithm", "key_size", "key_curve", "serial_hex", "sha256", "node_key",
                                  "cipher_suite", "san_json", "derived_at_not_a_token", "subject"])
def test_raw_material_detector_allows_legitimate_names(name):
    assert not is_raw_material_name(name)


def test_no_column_is_named_like_raw_material(conn):
    offenders = [(t, c) for t, c, _ in columns(conn) if is_raw_material_name(c)]
    assert offenders == []


def test_no_table_is_named_like_raw_material(conn):
    assert [t for t in table_names(conn) if is_raw_material_name(t)] == []


def test_no_blob_columns_and_only_plain_types(conn):
    types = {t for _, _, t in columns(conn)}
    assert types <= {"TEXT", "INTEGER"}, types
    assert not any("BLOB" in t for t in types)


def test_every_table_is_strict(conn):
    for row in conn.execute("PRAGMA table_list"):
        if row["schema"] == "main" and not row["name"].startswith("sqlite_"):
            assert row["strict"] == 1, row["name"]


def test_binary_values_are_rejected_by_strict_text_columns(conn):
    run_id = make_run(conn)
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "certificates", cert_row(run_id, subject=b"\x30\x82\x01\x0a"))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "fs_observations", fs_row(run_id, path=b"binary"))


def test_wrong_types_are_rejected(conn):
    run_id = make_run(conn)
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "fs_observations", fs_row(run_id, seq="not a number"))


# ------------------------------------------------------------------ enums agree with Phase 1 and the state machine
def test_run_status_enum_matches_the_state_machine(conn):
    assert check_values(conn, "runs", "status") == set(run_state.STATUSES)


def test_parse_status_enum_matches_the_agent(conn):
    assert check_values(conn, "fs_observations", "parse_status") == set(observations.ALL_STATUSES)


def test_other_fs_enums_match_the_agent(conn):
    assert check_values(conn, "fs_observations", "chain_role") == {"self_signed", "ca", "leaf"}
    assert check_values(conn, "fs_observations", "validity_status") == {"valid", "expiring", "expired"}
    assert check_values(conn, "fs_observations", "evidence_confidence") == {"high", "medium", "low"}
    assert check_values(conn, "fs_observations", "format") == {"pem", "der", "pkcs12", "unknown"}


def test_agent_statuses_all_insert_with_matching_shape(conn):
    run_id = make_run(conn)
    make_cert(conn, run_id)
    for seq, status in enumerate(observations.ALL_STATUSES):
        row = fs_row(run_id, seq) if status == "ok" else fs_failure_row(run_id, seq, parse_status=status)
        insert(conn, "fs_observations", row)
    assert conn.execute("SELECT count(*) FROM fs_observations").fetchone()[0] == len(observations.ALL_STATUSES)


def test_run_type_trigger_and_edge_enums(conn):
    assert check_values(conn, "runs", "type") == {"filesystem", "tls"}
    assert check_values(conn, "runs", "run_trigger") == {"manual", "scheduled"}
    assert check_values(conn, "edges", "kind") == {"communicates_with", "presented_certificate", "stored_on"}
    assert check_values(conn, "nodes", "kind") == {"host", "process", "certificate", "endpoint"}
    assert check_values(conn, "run_issues", "source") == {"agent", "backend"}


@pytest.mark.parametrize("table, make, column, bad", [
    ("runs", lambda c: run_row(), "type", "dns"),
    ("runs", lambda c: run_row(), "run_trigger", "api"),
    ("runs", lambda c: run_row(), "status", "cancelled"),
    ("schedules", lambda c: dict(schedule_id="s1", run_type="tls", interval_seconds=60, created_at=T_S), "run_type", "x"),
])
def test_invalid_enum_values_are_rejected(conn, table, make, column, bad):
    row = make(conn)
    row[column] = bad
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, table, row)


# ------------------------------------------------------------------ runs
def test_valid_runs_in_each_status_shape(conn):
    make_run(conn)                                                                            # queued
    make_run(conn, status="running", started_at=T_MS)
    make_run(conn, status="completed", started_at=T_MS, finished_at=T_MS, duration_ms=0)
    make_run(conn, status="partial", started_at=T_MS, finished_at=T_MS, duration_ms=0, error_summary="file_errors:1")
    make_run(conn, status="failed", started_at=T_MS, finished_at=T_MS, duration_ms=0, error_summary="agent_lost")
    make_run(conn, status="failed", finished_at=T_MS, error_summary="agent_not_connected")  # never started


@pytest.mark.parametrize("overrides", [
    dict(status="queued", started_at=T_MS),                                                   # queued must not have started
    dict(status="queued", duration_ms=5),
    dict(status="running"),                                                                   # running needs started_at
    dict(status="running", started_at=T_MS, finished_at=T_MS),
    dict(status="completed", started_at=T_MS, finished_at=T_MS),                              # no duration
    dict(status="completed", finished_at=T_MS, duration_ms=0),                                # never started
    dict(status="partial", started_at=T_MS, finished_at=T_MS, duration_ms=0),                 # partial needs a reason
    dict(status="failed", finished_at=T_MS),                                                  # failed needs a reason
    dict(status="failed", started_at=T_MS, finished_at=T_MS, error_summary="x"),              # started but no duration
    dict(status="failed", finished_at=T_MS, duration_ms=3, error_summary="x"),                # duration without a start
    dict(status="completed", started_at="2026-01-01T00:00:05.000Z", finished_at="2026-01-01T00:00:01.000Z",
         duration_ms=0),                                                                      # finished before started
    dict(status="completed", started_at=T_MS, finished_at=T_MS, duration_ms=-1),
    dict(queued_at="2026-01-01 00:00:00"),                                                    # not the fixed UTC format
    dict(queued_at=T_S),                                                                      # run times need milliseconds
    dict(queued_at="2026-01-01T00:00:00.000+00:00"),
    dict(record_count=-1), dict(finding_count=-1), dict(rejected_count=-1), dict(error_count=-1),
    dict(cancel_requested=2), dict(config_json="[1]"), dict(config_json="not json"),
    dict(agent_summary_json="{broken"),
    dict(run_trigger="manual", schedule_id="nope"),                                           # manual runs have no schedule
    dict(run_id="short"), dict(run_number=0),
])
def test_invalid_runs_are_rejected(conn, overrides):
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "runs", run_row(**overrides))


def test_run_number_and_id_are_unique(conn):
    first = run_row()
    insert(conn, "runs", first)
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "runs", run_row(run_number=first["run_number"]))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "runs", run_row(run_id=first["run_id"]))


def test_scheduled_run_must_reference_an_existing_schedule(conn):
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "runs", run_row(run_trigger="scheduled", schedule_id="missing"))
    insert(conn, "schedules", dict(schedule_id="s1", run_type="filesystem", interval_seconds=3600, created_at=T_S))
    insert(conn, "runs", run_row(run_trigger="scheduled", schedule_id="s1"))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "schedules", dict(schedule_id="s2", run_type="tls", interval_seconds=0, created_at=T_S))


# ------------------------------------------------------------------ certificates
def test_certificate_constraints(conn):
    run_id = make_run(conn)
    make_cert(conn, run_id)
    for bad in (dict(sha256="A" * 64), dict(sha256="a" * 63), dict(sha256="g" * 64), dict(san_json="{}"),
                dict(san_json="nope"), dict(key_size=0), dict(is_ca=2), dict(not_after="2027-01-01"),
                dict(first_seen_run="missing-run")):
        row = cert_row(run_id, SHA_B)
        row.update(bad)
        with pytest.raises(sqlite3.IntegrityError):
            insert(conn, "certificates", row)
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "certificates", cert_row(run_id, SHA_A))                                 # catalog is unique by sha256


def test_certificate_with_unknown_key_size_and_ca_flag_is_allowed(conn):
    run_id = make_run(conn)
    insert(conn, "certificates", cert_row(run_id, key_size=None, is_ca=None, key_curve=None))


# ------------------------------------------------------------------ filesystem observations
def test_pfx_duplicate_sightings_in_one_file_are_not_collapsed(conn):
    run_id = make_run(conn)
    make_cert(conn, run_id)
    for seq in range(3):                                           # the same certificate three times in one .pfx
        insert(conn, "fs_observations", fs_row(run_id, seq, entry_ordinal=seq, path="C:\\p\\a.pfx", format="pkcs12",
                                               chain_index=None, chain_total=3))
    assert conn.execute("SELECT count(*) FROM fs_observations WHERE sha256 = ?", (SHA_A,)).fetchone()[0] == 3
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "fs_observations", fs_row(run_id, 1, entry_ordinal=9))                   # (run_id, seq) is the identity


def test_fs_row_invariants(conn):
    run_id = make_run(conn)
    make_cert(conn, run_id)
    bad_rows = {
        "ok without a fingerprint": fs_row(run_id, 1, sha256=None, chain_role=None, validity_status=None,
                                           days_to_expiry=None, not_yet_valid=None),
        "failure carrying a fingerprint": fs_failure_row(run_id, 2, sha256=SHA_A),
        "failure carrying certificate fields": fs_failure_row(run_id, 3, chain_role="leaf"),
        "failure carrying validity": fs_failure_row(run_id, 4, validity_status="valid"),
        "failure with days_to_expiry": fs_failure_row(run_id, 5, days_to_expiry=3),
        "failure with high confidence": fs_failure_row(run_id, 6, evidence_confidence="high"),
        "pkcs12 with a chain position": fs_row(run_id, 7, format="pkcs12", chain_index=0),
        "ok certificate missing role": fs_row(run_id, 8, chain_role=None),
        "ok certificate missing validity": fs_row(run_id, 9, validity_status=None),
        "integrity warning at high confidence": fs_row(run_id, 10, format="pkcs12", chain_index=None,
                                                       warnings_json='["pkcs12_integrity_not_verified"]'),
        "unknown parse_status": fs_failure_row(run_id, 11, parse_status="weird"),
        "unknown format": fs_row(run_id, 12, format="jks"),
        "unknown fingerprint": fs_row(run_id, 13, sha256=SHA_B),
        "bad discovered_at": fs_row(run_id, 14, discovered_at="yesterday"),
        "warnings not an array": fs_row(run_id, 15, warnings_json="{}"),
        "negative ordinal": fs_row(run_id, 16, entry_ordinal=-1),
        "bad extension_mismatch": fs_row(run_id, 17, extension_mismatch=5),
        "owning process not an object": fs_row(run_id, 18, owning_process_json="[]"),
        "unknown run": fs_row("missing-run", 19),
    }
    for label, row in bad_rows.items():
        with pytest.raises(sqlite3.IntegrityError):
            insert(conn, "fs_observations", row)
        assert conn.execute("SELECT count(*) FROM fs_observations").fetchone()[0] == 0, label


def test_valid_fs_rows(conn):
    run_id = make_run(conn)
    make_cert(conn, run_id)
    insert(conn, "fs_observations", fs_row(run_id, 1))
    insert(conn, "fs_observations", fs_row(run_id, 2, format="pkcs12", chain_index=None, evidence_confidence="medium",
                                           warnings_json='["pkcs12_integrity_not_verified"]'))
    insert(conn, "fs_observations", fs_failure_row(run_id, 3))
    insert(conn, "fs_observations", fs_row(run_id, 4, not_yet_valid=1, validity_status="expired", days_to_expiry=-4,
                                           owning_process_json='{"pid": 4}'))


# ------------------------------------------------------------------ TLS
def test_tls_row_constraints(conn):
    run_id = make_run(conn, type="tls")
    insert(conn, "tls_observations", tls_row(run_id, 0))
    insert(conn, "tls_observations", tls_row(run_id, 1, tls_version="TLS1.3", cert_visibility="encrypted_tls13",
                                             pid=4242, process_attribution="attributed", event_count=7))
    for seq, bad in enumerate((dict(direction="sideways"), dict(transport="udp"), dict(src_port=70000),
                               dict(dst_port=-1), dict(handshake_outcome="great"), dict(tls_version="TLS9"),
                               dict(cert_visibility="maybe"), dict(event_count=-1), dict(packet_count=-1),
                               dict(pid=-3), dict(process_attribution="guessed"), dict(event_counts_json="[]"),
                               dict(observed_at="soon"), dict(local_port=99999), dict(cipher_id=70000),
                               dict(evidence_confidence="certain")), start=10):
        with pytest.raises(sqlite3.IntegrityError):
            insert(conn, "tls_observations", tls_row(run_id, seq, **bad))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "tls_observations", tls_row(run_id, 0))                                  # (run_id, seq) unique


def test_tls_certificates_are_normalized_through_peer_certificates(conn):
    run_id = make_run(conn, type="tls")
    assert "cert_sha256" not in {c for t, c, _ in columns(conn) if t == "tls_observations"}
    make_cert(conn, run_id, SHA_A)
    make_cert(conn, run_id, SHA_B)
    obs = insert(conn, "tls_observations", tls_row(run_id, 0)).lastrowid
    insert(conn, "tls_peer_certificates", dict(tls_observation_id=obs, position=0, sha256=SHA_A))
    insert(conn, "tls_peer_certificates", dict(tls_observation_id=obs, position=1, sha256=SHA_B))
    for bad in (dict(tls_observation_id=obs, position=0, sha256=SHA_B),                       # position already used
                dict(tls_observation_id=obs, position=2, sha256="c" * 64),                    # unknown certificate
                dict(tls_observation_id=obs + 99, position=0, sha256=SHA_A),                  # unknown connection
                dict(tls_observation_id=obs, position=-1, sha256=SHA_A)):
        with pytest.raises(sqlite3.IntegrityError):
            insert(conn, "tls_peer_certificates", bad)


def test_same_certificate_may_appear_in_many_connections(conn):
    run_id = make_run(conn, type="tls")
    make_cert(conn, run_id)
    for seq in range(3):
        obs = insert(conn, "tls_observations", tls_row(run_id, seq)).lastrowid
        insert(conn, "tls_peer_certificates", dict(tls_observation_id=obs, position=0, sha256=SHA_A))
    assert conn.execute("SELECT count(*) FROM tls_peer_certificates WHERE sha256 = ?", (SHA_A,)).fetchone()[0] == 3


# ------------------------------------------------------------------ graph
def test_graph_uniqueness_and_counts(conn):
    process = make_node(conn, "process", "C:\\app\\app.exe")
    endpoint = make_node(conn, "endpoint", "93.184.216.34:443/tcp")
    with pytest.raises(sqlite3.IntegrityError):
        make_node(conn, "process", "C:\\app\\app.exe")                                        # (kind, key) unique
    make_node(conn, "endpoint", "C:\\app\\app.exe")                                           # same key, other kind is fine
    insert(conn, "edges", edge_row(process, endpoint, "communicates_with"))
    for bad in (edge_row(process, endpoint, "communicates_with"),                             # (src, dst, kind) unique
                edge_row(process, endpoint, "communicates_with", observation_count=0),
                edge_row(process, process, "communicates_with"),
                edge_row(process, endpoint, "talks_to"),
                edge_row(process, 9999, "communicates_with")):
        with pytest.raises(sqlite3.IntegrityError):
            insert(conn, "edges", bad)


def test_edge_kinds_are_exactly_the_three_atomic_ones(conn):
    assert check_values(conn, "edges", "kind") == {"communicates_with", "presented_certificate", "stored_on"}


def test_edge_kinds_connect_only_the_intended_node_kinds(conn):
    nodes = {kind: make_node(conn, kind, f"{kind}-1") for kind in ("host", "process", "certificate", "endpoint")}
    nodes["endpoint2"] = make_node(conn, "endpoint", "endpoint-2")
    allowed = [
        ("process", "endpoint", "communicates_with"), ("host", "endpoint2", "communicates_with"),
        ("endpoint", "certificate", "presented_certificate"), ("process", "certificate", "presented_certificate"),
        ("host", "certificate", "presented_certificate"), ("certificate", "host", "stored_on"),
    ]
    for src, dst, kind in allowed:
        insert(conn, "edges", edge_row(nodes[src], nodes[dst], kind))
    refused = [
        ("certificate", "endpoint", "communicates_with"),       # a certificate does not communicate
        ("process", "certificate", "communicates_with"),        # no direct process -> certificate "communication"
        ("endpoint", "process", "communicates_with"),           # direction matters
        ("certificate", "endpoint", "presented_certificate"),
        ("process", "endpoint", "presented_certificate"),
        ("host", "certificate", "stored_on"),                   # stored_on runs certificate -> host
        ("certificate", "process", "stored_on"),
    ]
    for src, dst, kind in refused:
        with pytest.raises(sqlite3.IntegrityError, match="edge kind does not match node kinds"):
            insert(conn, "edges", edge_row(nodes[src], nodes[dst], kind))


def test_edge_update_cannot_bypass_the_node_kind_rule(conn):
    process = make_node(conn, "process", "p")
    endpoint = make_node(conn, "endpoint", "e")
    cert = make_node(conn, "certificate", "c")
    edge = insert(conn, "edges", edge_row(process, endpoint, "communicates_with")).lastrowid
    with pytest.raises(sqlite3.IntegrityError, match="edge kind does not match node kinds"):
        conn.execute("UPDATE edges SET dst_node = ? WHERE edge_id = ?", (cert, edge))
    conn.execute("UPDATE edges SET observation_count = observation_count + 1 WHERE edge_id = ?", (edge,))   # strengthening is fine


def test_edge_runs_track_per_run_contribution(conn):
    run_a, run_b = make_run(conn), make_run(conn)
    process = make_node(conn, "process", "p")
    endpoint = make_node(conn, "endpoint", "e")
    edge = insert(conn, "edges", edge_row(process, endpoint, "communicates_with", observation_count=5, run_count=2)).lastrowid
    insert(conn, "edge_runs", dict(edge_id=edge, run_id=run_a, observation_count=2, first_at=T_S, last_at=T_S))
    insert(conn, "edge_runs", dict(edge_id=edge, run_id=run_b, observation_count=3, first_at=T_S, last_at=T_S))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "edge_runs", dict(edge_id=edge, run_id=run_a, observation_count=1, first_at=T_S, last_at=T_S))
    with pytest.raises(sqlite3.IntegrityError):
        insert(conn, "edge_runs", dict(edge_id=edge, run_id="missing-run", observation_count=1, first_at=T_S, last_at=T_S))


# ------------------------------------------------------------------ indexes
def index_columns(conn, table):
    out = []
    for idx in conn.execute(f"PRAGMA index_list({table})"):
        out.append((idx["name"], [r["name"] for r in conn.execute(f"PRAGMA index_info({idx['name']})")]))
    return out


def has_index(conn, table, cols):
    return any(found[:len(cols)] == list(cols) for _, found in index_columns(conn, table))


@pytest.mark.parametrize("table, cols", [
    ("runs", ["status", "queued_at"]), ("runs", ["type", "status"]), ("runs", ["started_at"]),
    ("fs_observations", ["run_id", "seq"]), ("fs_observations", ["run_id", "sha256"]),
    ("fs_observations", ["run_id", "parse_status"]), ("fs_observations", ["run_id", "validity_status"]),
    ("fs_observations", ["run_id", "scan_root"]), ("fs_observations", ["run_id", "path"]),
    ("fs_observations", ["sha256"]),
    ("certificates", ["not_after"]), ("certificates", ["key_algorithm", "key_size"]), ("certificates", ["issuer"]),
    ("tls_observations", ["run_id", "seq"]), ("tls_observations", ["run_id", "remote_ip", "remote_port"]),
    ("tls_observations", ["run_id", "tls_version"]), ("tls_observations", ["run_id", "cipher_suite"]),
    ("tls_observations", ["run_id", "observed_at"]), ("tls_observations", ["run_id", "process_name"]),
    ("tls_peer_certificates", ["sha256"]),
    ("nodes", ["kind", "node_key"]), ("edges", ["src_node", "dst_node", "kind"]), ("edges", ["dst_node"]),
    ("edges", ["kind", "last_seen_at"]), ("edge_runs", ["run_id"]), ("run_issues", ["run_id"]),
    ("run_issues", ["run_id", "kind", "seq"]),                       # migration 0002: rejected-seq lookup
])
def test_expected_indexes_exist(conn, table, cols):
    assert has_index(conn, table, cols), f"missing index on {table}{cols}"


def test_there_is_no_index_on_tls_observations_certificate(conn):
    for _, cols in index_columns(conn, "tls_observations"):
        assert not any("cert" in c and "visibility" not in c for c in cols)


def plan(conn, sql, params=()):
    return " ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))


def test_hot_queries_use_indexes(conn):
    assert "idx_fs_run_sha256" in plan(conn, "SELECT * FROM fs_observations WHERE run_id = ? AND sha256 = ?", ("r", SHA_A))
    assert "idx_fs_run_parse" in plan(conn, "SELECT * FROM fs_observations WHERE run_id = ? AND parse_status = ?", ("r", "ok"))
    assert "idx_tls_peer_certificates_sha256" in plan(conn, "SELECT * FROM tls_peer_certificates WHERE sha256 = ?", (SHA_A,))
    assert "idx_runs_active" in plan(conn, "SELECT * FROM runs WHERE status = 'queued' ORDER BY queued_at LIMIT 1")
    assert "idx_certificates_not_after" in plan(conn, "SELECT * FROM certificates WHERE not_after < ?", (T_S,))
