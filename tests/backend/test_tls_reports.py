"""TLS report queries over stored probe evidence: counts, filters, sorts, paging, frontier, isolation, and what is never reported."""
import json

import pytest

from backend import db, runs, tls_ingest, tls_reports
from backend.reports import InvalidQuery
from backend.tls_reports import TlsObservationQuery
from ingestfx import running_run
from tlsingestfx import (NOW, at, build_tls_records, failed_record, finish, ingest, peer, running_tls_run, tls_error, tls_record,
                         tls_summary)

OBSERVATION_KEYS = {"seq", "observed_at", "direction", "transport", "src_ip", "src_port", "dst_ip", "dst_port", "handshake_outcome", "sni",
                    "tls_version", "cipher_suite", "cert_visibility", "pid", "process_name", "exe_path", "process_attribution",
                    "event_count", "packet_count", "event_counts", "evidence_confidence", "warnings", "peer_certificates"}
PEER_KEYS = {"position", "sha256", "subject", "issuer", "not_before", "not_after", "key_algorithm", "key_size", "key_curve",
             "signature_algorithm", "is_ca"}


@pytest.fixture
def loaded(conn):
    run = running_tls_run(conn)
    records = build_tls_records()
    ingest(conn, run, records)
    return conn, run, records


def O(conn, run, **kw):
    with db.read_snapshot(conn):
        return tls_reports.search_observations(conn, run, TlsObservationQuery(**kw))


def SUM(conn, run, **kw):
    kw.setdefault("now", NOW)
    with db.read_snapshot(conn):
        return tls_reports.tls_summary(conn, run, **kw)


def ISS(conn, run, **kw):
    with db.read_snapshot(conn):
        return tls_reports.list_tls_issues(conn, run, **kw)


def seqs(page):
    return [i["seq"] for i in page.items]


# ------------------------------------------------------------------ summary counts
def test_the_summary_separates_probe_attempts_from_completed_handshakes(loaded):
    conn, run, _ = loaded
    s = SUM(conn, run)
    assert s["totals"] == {"probe_attempts": 10, "handshakes_completed": 6, "not_completed": 4, "endpoints": 10,
                           "certificates_presented": 7, "leaf_certificates": 5}
    assert s["outcomes"] == {"completed": 6, "failed": 1, "alert": 1, "incomplete": 1, "unknown": 1}
    assert s["run"] == {"run_id": run, "run_number": 1, "type": "tls", "status": "running", "final": False,
                        "started_at": "2026-03-01T12:00:01.000Z", "finished_at": None}


def test_versions_ciphers_and_attribution_count_only_what_they_describe(loaded):
    conn, run, _ = loaded
    s = SUM(conn, run)
    assert s["tls_versions"] == {"SSL3": 0, "TLS1.0": 0, "TLS1.1": 0, "TLS1.2": 1, "TLS1.3": 5}              # completed handshakes only
    assert s["cipher_suites"]["top"] == [{"cipher_suite": "TLS_AES_256_GCM_SHA384", "handshakes": 5},
                                         {"cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "handshakes": 1}]
    assert s["cipher_suites"]["other"] is None and s["cipher_suites"]["total_groups"] == 2
    assert s["process_attribution"] == {"attributed": 4, "not_found": 1, "unavailable": 5}
    assert sum(s["tls_versions"].values()) == s["totals"]["handshakes_completed"]


def test_failed_and_inconclusive_probes_never_count_as_findings(loaded):
    conn, run, _ = loaded
    s = SUM(conn, run)
    assert s["outcomes"]["completed"] == s["totals"]["handshakes_completed"] == 6
    assert s["totals"]["not_completed"] == s["outcomes"]["failed"] + s["outcomes"]["alert"] + s["outcomes"]["incomplete"] + s["outcomes"]["unknown"]
    assert s["totals"]["certificates_presented"] == 7                          # no certificate belongs to a non-completed probe


def test_ciphers_are_ranked_with_an_other_bucket(conn):
    run = running_tls_run(conn)
    ingest(conn, run, [tls_record(i, port=8000 + i, cipher_suite=f"CIPHER_{i % 5}") for i in range(1, 11)])
    ranked = SUM(conn, run, top_n=2)["cipher_suites"]
    assert len(ranked["top"]) == 2 and ranked["total_groups"] == 5 and ranked["limit"] == 2
    assert ranked["other"] == {"groups": 3, "handshakes": 6} and sum(i["handshakes"] for i in ranked["top"]) + 6 == 10


def test_certificate_validity_is_judged_per_unique_leaf_certificate_at_the_request_time(loaded):
    conn, run, _ = loaded
    s = SUM(conn, run)
    assert s["certificate_validity"] == {"expiring_days": {"value": 30, "source": "default"},
                                         "now": {"valid": 3, "expiring": 1, "expired": 1, "not_yet_valid": 1}}
    later = SUM(conn, run, now=at(86400 * 1000))                                 # 1000 days on, everything issued has run out
    assert later["certificate_validity"]["now"] == {"valid": 0, "expiring": 0, "expired": 5, "not_yet_valid": 0}


def test_a_leaf_certificate_seen_twice_is_one_certificate(loaded):
    conn, run, _ = loaded
    assert SUM(conn, run)["totals"]["leaf_certificates"] == 5 and SUM(conn, run)["totals"]["certificates_presented"] == 7


def test_the_summary_agrees_with_the_run_counters_without_a_frontier(loaded):
    conn, run, _ = loaded
    finish(conn, run, summary=tls_summary(10, completed=6, errors=[tls_error("probe", "target_not_local")]))
    s, state = SUM(conn, run), runs.load_state(conn, run)
    assert s["totals"]["probe_attempts"] == state.record_count and s["totals"]["handshakes_completed"] == state.finding_count
    assert s["issues"]["errors"]["total"] == state.error_count and s["issues"]["rejected"] == state.rejected_count


def test_issue_counts_are_split_by_who_found_them(conn):
    run = running_tls_run(conn)
    bad = tls_record(2)
    bad["packet_count"] = 5
    ingest(conn, run, [tls_record(1), bad])
    ingest(conn, run, [tls_record(1, tls_version="TLS1.2")], start=0, now=at(3))                       # a conflict on seq 0
    finish(conn, run, summary=tls_summary(2, completed=1, errors=[tls_error("probe", "target_not_local"), tls_error("enumerate", "table_unreadable")]))
    assert SUM(conn, run)["issues"] == {"errors": {"total": 2, "enumerate": 1, "probe": 1}, "rejected": 1, "seq_conflicts": 1}


# ------------------------------------------------------------------ scan facts: zero listeners is not a failed enumeration
def test_scan_facts_exist_only_after_the_run_finished(loaded):
    conn, run, _ = loaded
    assert SUM(conn, run)["scan"] is None
    finish(conn, run, summary=tls_summary(10, completed=6, listeners_found=12, policy_skipped=2, port_filtered=1, targets_planned=10, targets_probed=10))
    assert SUM(conn, run)["scan"] == {"stop_reason": "completed", "enumeration": "ok", "listeners_found": 12, "port_filtered": 1,
                                      "policy_skipped": 2, "targets_planned": 10, "targets_probed": 10, "targets_truncated": False}


def test_zero_eligible_listeners_and_a_failed_enumeration_look_different(conn):
    quiet, broken = running_tls_run(conn), running_tls_run(conn)
    finish(conn, quiet, summary=tls_summary(0, listeners_found=4, policy_skipped=4, targets_planned=0, targets_probed=0))
    finish(conn, broken, summary=tls_summary(0, enumeration="failed", stop_reason="enumeration_failed", errors=[tls_error("enumerate", "table_unreadable")]))
    a, b = SUM(conn, quiet), SUM(conn, broken)
    assert a["totals"]["probe_attempts"] == b["totals"]["probe_attempts"] == 0
    assert (a["scan"]["enumeration"], a["scan"]["listeners_found"], a["issues"]["errors"]["total"]) == ("ok", 4, 0)
    assert (b["scan"]["enumeration"], b["scan"]["stop_reason"], b["issues"]["errors"]["enumerate"]) == ("failed", "enumeration_failed", 1)
    assert (a["run"]["status"], b["run"]["status"]) == ("completed", "failed")


def test_an_unusable_stored_summary_gives_no_scan_facts(conn):
    run = running_tls_run(conn)
    finish(conn, run, summary={"enumeration": "maybe"})
    assert SUM(conn, run)["scan"] is None


def test_an_empty_run_has_zero_filled_shapes(conn):
    run = running_tls_run(conn)
    s = SUM(conn, run)
    assert s["totals"] == {"probe_attempts": 0, "handshakes_completed": 0, "not_completed": 0, "endpoints": 0, "certificates_presented": 0, "leaf_certificates": 0}
    assert set(s["outcomes"]) == {"completed", "failed", "alert", "incomplete", "unknown"} and sum(s["outcomes"].values()) == 0
    assert set(s["tls_versions"]) == {"SSL3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
    assert s["cipher_suites"] == {"top": [], "other": None, "total_groups": 0, "limit": 20}
    assert s["certificate_validity"]["now"] == {"valid": 0, "expiring": 0, "expired": 0, "not_yet_valid": 0} and s["frontier"] == 0


# ------------------------------------------------------------------ observations
def test_a_page_of_observations_has_exactly_the_published_fields(loaded):
    conn, run, _ = loaded
    page = O(conn, run)
    assert page.total == 10 and page.limit == 100 and page.offset == 0 and seqs(page) == list(range(10))
    for item in page.items:
        assert set(item) == OBSERVATION_KEYS
        assert all(set(p) == PEER_KEYS for p in item["peer_certificates"])
    first = page.items[0]
    assert (first["direction"], first["transport"], first["sni"], first["event_count"], first["packet_count"]) == ("unknown", "tcp", None, 1, 0)
    assert first["event_counts"] == {"probe_attempts": 1, "handshake_completed": 1}
    assert first["warnings"] == ["active_probe", "packet_counts_unavailable"]
    assert (first["src_ip"], first["src_port"], first["dst_ip"], first["dst_port"]) == ("127.0.0.1", 50001, "127.0.0.1", 8443)


def test_peer_certificates_are_leaf_first_and_a_certificate_may_be_presented_more_than_once(loaded):
    conn, run, _ = loaded
    page = O(conn, run)
    chain = page.items[0]["peer_certificates"]
    assert [(p["position"], p["subject"]) for p in chain] == [(0, "CN=cert1"), (1, "CN=cert2"), (2, "CN=cert3")]
    assert chain[1]["is_ca"] is True and chain[0]["is_ca"] is False
    assert page.items[2]["peer_certificates"] == chain                                   # the same certificate again: a second observation
    assert page.items[3]["peer_certificates"] == [] and page.items[3]["cert_visibility"] == "not_observed"


def test_inconclusive_probes_have_no_version_cipher_or_certificate(loaded):
    conn, run, _ = loaded
    for item in O(conn, run, outcome="failed").items + O(conn, run, outcome="alert").items + O(conn, run, outcome="incomplete").items + O(conn, run, outcome="unknown").items:
        assert item["tls_version"] is None and item["cipher_suite"] is None and item["peer_certificates"] == []
        assert item["evidence_confidence"] == "low"


def test_peers_for_a_whole_page_are_fetched_with_one_query(loaded):
    conn, run, _ = loaded
    statements = []
    conn.set_trace_callback(statements.append)
    try:
        O(conn, run, limit=10)
    finally:
        conn.set_trace_callback(None)
    assert sum("tls_peer_certificates AS p " in s for s in statements) == 1


@pytest.mark.parametrize("filters,expected", [
    (dict(outcome="completed"), [0, 1, 2, 7, 8, 9]), (dict(outcome="failed"), [3]), (dict(outcome="incomplete"), [4]),
    (dict(outcome="alert"), [5]), (dict(outcome="unknown"), [6]),
    (dict(tls_version="TLS1.2"), [1]), (dict(tls_version="TLS1.3"), [0, 2, 7, 8, 9]), (dict(tls_version="SSL3"), []),
    (dict(process_attribution="not_found"), [1]), (dict(process_attribution="attributed"), [0, 7, 8, 9]),
    (dict(process_attribution="unavailable"), [2, 3, 4, 5, 6]), (dict(dst_port=8443), [0]), (dict(dst_port=65535), []),
    (dict(outcome="completed", tls_version="TLS1.3", process_attribution="attributed"), [0, 7, 8, 9]),
])
def test_filters(loaded, filters, expected):
    conn, run, _ = loaded
    page = O(conn, run, **filters)
    assert seqs(page) == expected and page.total == len(expected)


def test_the_fingerprint_filter_matches_any_chain_position_by_prefix(conn):
    run = running_tls_run(conn)
    a, b, c = "ab12" + "0" * 60, "ab34" + "0" * 60, "cd56" + "0" * 60
    ingest(conn, run, [tls_record(1, port=8001, peers=[peer(1, sha256=a), peer(2, sha256=c, is_ca=True)]),
                       tls_record(2, port=8002, peers=[peer(2, sha256=b)]), failed_record(9000)])
    assert seqs(O(conn, run, fingerprint="ab12")) == [0] and seqs(O(conn, run, fingerprint="ab34")) == [1]
    assert seqs(O(conn, run, fingerprint=c)) == [0]                                    # an intermediate certificate in the chain
    assert seqs(O(conn, run, fingerprint="AB12")) == [0] and O(conn, run, fingerprint="ef" * 20).total == 0


@pytest.mark.parametrize("q,expected", [
    ("python.exe", [0]), ("PYTHON", [0]), ("C:\\Python311", [0]), ("127.0.0.1", list(range(10))), ("cert4", [1]), ("CN=CERT5", [7]),
    ("nothing-matches", []), ("%", []), ("_", []), ("cert_", []),
])
def test_text_search_covers_address_process_path_and_leaf_subject_with_literal_wildcards(loaded, q, expected):
    conn, run, _ = loaded
    assert seqs(O(conn, run, q=q)) == expected


def test_search_does_not_match_a_non_leaf_certificate(loaded):
    conn, run, _ = loaded
    assert O(conn, run, q="cert2").total == 0 and O(conn, run, q="cert3").total == 0     # only the leaf subject is searched


@pytest.mark.parametrize("sort", sorted(tls_reports.TLS_SORTS))
@pytest.mark.parametrize("direction", ["asc", "desc"])
def test_every_sort_gives_a_total_order_with_missing_values_last(loaded, sort, direction):
    conn, run, _ = loaded
    page = O(conn, run, sort=sort, direction=direction)
    assert sorted(seqs(page)) == list(range(10)) and len(set(seqs(page))) == 10
    key = {"seq": "seq", "observed_at": "observed_at", "dst_ip": "dst_ip", "dst_port": "dst_port", "handshake_outcome": "handshake_outcome",
           "tls_version": "tls_version", "cipher_suite": "cipher_suite", "process_name": "process_name"}[sort]
    values = [i[key] for i in page.items]
    present = [v for v in values if v is not None]
    assert values[:len(present)] == present and all(v is None for v in values[len(present):])        # NULLs last
    folded = [v.casefold() if isinstance(v, str) else v for v in present]
    assert folded == sorted(folded, reverse=direction == "desc")


def test_ties_break_by_seq_ascending(loaded):
    conn, run, _ = loaded
    page = O(conn, run, sort="tls_version", direction="desc")
    assert seqs(page)[:5] == [0, 2, 7, 8, 9]                                         # five TLS1.3 rows in seq order


def test_paging_covers_everything_once_and_the_total_ignores_limit_and_offset(loaded):
    conn, run, _ = loaded
    seen, offset = [], 0
    while True:
        page = O(conn, run, limit=3, offset=offset)
        assert page.total == 10
        seen += seqs(page)
        offset += 3
        if offset >= page.total:
            break
    assert seen == list(range(10)) and O(conn, run, limit=3, offset=9).items[0]["seq"] == 9 and O(conn, run, offset=50).items == []


def test_the_frontier_keeps_pages_consistent_while_a_scan_is_still_adding_rows(loaded):
    conn, run, _ = loaded
    first = O(conn, run, limit=4)
    ingest(conn, run, [tls_record(9, port=8500, src_port=51000), failed_record(9100, src_port=51001)], start=10, now=at(5))
    pinned = O(conn, run, limit=4, offset=4, frontier=first.frontier)
    assert pinned.total == 10 and seqs(pinned) == [4, 5, 6, 7] and pinned.frontier == first.frontier
    fresh = O(conn, run)
    assert fresh.total == 12 and fresh.frontier > first.frontier
    summary = SUM(conn, run, frontier=first.frontier)
    assert summary["totals"]["probe_attempts"] == 10 and summary["frontier"] == first.frontier and SUM(conn, run)["totals"]["probe_attempts"] == 12


@pytest.mark.parametrize("kwargs,field,problem", [
    (dict(outcome="bogus"), "outcome", "unknown_value"), (dict(outcome=5), "outcome", "wrong_type"),
    (dict(tls_version="TLSv1.3"), "tls_version", "unknown_value"), (dict(process_attribution="guessed"), "process_attribution", "unknown_value"),
    (dict(dst_port=0), "dst_port", "out_of_range"), (dict(dst_port=65536), "dst_port", "out_of_range"), (dict(dst_port=True), "dst_port", "wrong_type"),
    (dict(fingerprint="xyz"), "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"), (dict(fingerprint="abc"), "fingerprint", "not_a_hex_prefix_of_4_to_64_characters"),
    (dict(q=""), "q", "too_short"), (dict(q="x" * 201), "q", "too_long"), (dict(sort="path"), "sort", "unknown_value"),
    (dict(direction="up"), "direction", "unknown_value"), (dict(limit=0), "limit", "out_of_range"), (dict(limit=501), "limit", "out_of_range"),
    (dict(offset=-1), "offset", "out_of_range"), (dict(frontier=-1), "frontier", "out_of_range"),
])
def test_invalid_queries_are_refused_with_fixed_identifiers(kwargs, field, problem):
    with pytest.raises(InvalidQuery) as refusal:
        TlsObservationQuery(**kwargs)
    assert (refusal.value.field, refusal.value.problem) == (field, problem)


# ------------------------------------------------------------------ issues
def test_issues_list_agent_errors_and_backend_refusals_without_paths(conn):
    run = running_tls_run(conn)
    bad = tls_record(2)
    bad["direction"] = "inbound"
    ingest(conn, run, [tls_record(1), bad])
    finish(conn, run, summary=tls_summary(2, completed=1, errors=[tls_error("probe", "target_not_local"), tls_error("probe", "probe_internal_error")]))
    page = ISS(conn, run)
    assert page["total"] == 3 and (page["limit"], page["offset"]) == (100, 0)
    assert page["items"] == [{"source": "backend", "kind": "rejected_record", "code": "bad_direction", "path": None, "seq": 1},
                             {"source": "agent", "kind": "probe", "code": "target_not_local", "path": None, "seq": None},
                             {"source": "agent", "kind": "probe", "code": "probe_internal_error", "path": None, "seq": None}]
    assert [i["code"] for i in ISS(conn, run, limit=1, offset=1)["items"]] == ["target_not_local"] and ISS(conn, run, offset=9)["items"] == []


def test_a_run_without_issues_has_an_empty_list(loaded):
    conn, run, _ = loaded
    assert ISS(conn, run) == {"items": [], "total": 0, "limit": 100, "offset": 0}


@pytest.mark.parametrize("kwargs", [dict(limit=0), dict(limit=501), dict(offset=-1), dict(limit=None), dict(offset=None)])
def test_issue_paging_is_validated(conn, kwargs):
    run = running_tls_run(conn)
    with pytest.raises(InvalidQuery):
        ISS(conn, run, **kwargs)


# ------------------------------------------------------------------ run types, unknown runs, isolation, snapshots
@pytest.mark.parametrize("call", [lambda c, r: O(c, r), lambda c, r: SUM(c, r), lambda c, r: ISS(c, r)])
def test_a_filesystem_run_is_refused_and_an_unknown_run_is_not_found(conn, call):
    with pytest.raises(runs.WrongRunType):
        call(conn, running_run(conn))
    with pytest.raises(runs.RunNotFound):
        call(conn, "f" * 32)


def test_runs_never_see_each_others_rows(conn):
    a, b = running_tls_run(conn), running_tls_run(conn)
    ingest(conn, a, build_tls_records())
    ingest(conn, b, [tls_record(1, port=7000)])
    assert O(conn, a).total == 10 and O(conn, b).total == 1 and seqs(O(conn, b)) == [0]
    assert SUM(conn, b)["totals"]["probe_attempts"] == 1 and SUM(conn, b)["totals"]["certificates_presented"] == 1
    assert O(conn, b, dst_port=8443).total == 0 and ISS(conn, b)["total"] == 0


def test_reports_refuse_to_run_outside_a_snapshot(loaded):
    conn, run, _ = loaded
    for call in (lambda: tls_reports.search_observations(conn, run), lambda: tls_reports.tls_summary(conn, run, now=NOW),
                 lambda: tls_reports.list_tls_issues(conn, run)):
        with pytest.raises(db.TransactionRequired):
            call()


def test_reading_changes_nothing(loaded):
    conn, run, _ = loaded

    def everything():
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
        return {n: sorted(tuple(r) for r in conn.execute(f"SELECT * FROM {n}")) for n in names}

    before = everything()
    O(conn, run), O(conn, run, q="python"), SUM(conn, run), ISS(conn, run)
    assert everything() == before


def test_nothing_internal_or_secret_is_in_any_result(loaded):
    conn, run, _ = loaded
    finish(conn, run, summary=tls_summary(10, completed=6))
    text = json.dumps([O(conn, run).items, SUM(conn, run), ISS(conn, run)])
    for forbidden in ("internal_id", "local_ip", "remote_ip", "last_event_at", "cipher_id", "lease", "token", "BEGIN", "PRIVATE", "agent_summary_json"):
        assert forbidden not in text
    assert '"id"' not in text
    _ = (tls_ingest, peer)
