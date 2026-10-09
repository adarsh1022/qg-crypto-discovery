"""Fake-agent end-to-end tests over HTTP with the real Phase 1 scanner, plus genuinely concurrent requests."""
import asyncio
import hashlib
import itertools
import os

import httpx
import pytest

import pemgen
import pfxgen
from apifx import BASE_URL, TOKEN_HEADER, make_api
from backend import fs_queries
from backend.app import sweep_once
from ingestfx import ok_record, summary
from treegen import exclusive_lock, put, run_scan

ROOT_CERT, INTER, LEAF = pfxgen.chain()
CANCEL_AT = 13                      # the scanner's 13th stop-check falls after some, but not all, of the tree's files


def build_tree(base, with_keys=True):
    keys = pemgen.private_key_pems()
    put(base, "app/server.pem", pemgen.pem_encode(LEAF) + (keys["pkcs8_rsa"] if with_keys else b""))
    put(base, "backup/server.crt", LEAF)                                             # the same certificate again, as DER
    put(base, "store/dup.pfx", pfxgen.plain_with_key(extra_ca=(INTER, INTER, ROOT_CERT)))      # the inter twice in one file
    if with_keys:
        put(base, "keys/rsa.pem", keys["pkcs8_rsa"])
        put(base, "keys/ec.pem", keys["pkcs8_ec"])
    return base


def query(api, run_id):
    with api.connect() as conn:
        return fs_queries.fs_counts(conn, run_id), fs_queries.list_fs_observations(conn, run_id, limit=1000)


def new_run(api, tree, **config):
    return api.create(config={"roots": [str(tree)], **config})["run_id"]


# =========================================================================== the whole protocol, real scanner
def test_a_fake_agent_runs_a_real_scan_through_the_api(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    assert [r["status"] for r in api.client.get("/api/runs").json()["runs"]] == ["queued"]

    agent = api.agent()
    claim = agent.claim(run_id).json()
    assert claim["run"]["config"] == {"roots": [str(tree)]}                          # the agent learns what to scan from the claim
    api.clock.advance(5)
    assert agent.heartbeat().status_code == 200

    from treegen import run_scan as scan
    records, scan_summary = scan(*claim["run"]["config"]["roots"])
    uploads = agent.upload_records(records, batch_size=3)
    assert all(u.status_code == 200 for u in uploads) and sum(u.json()["accepted"] for u in uploads) == len(records)
    api.clock.advance(5)
    final = agent.finish(summary=scan_summary)
    run = final.json()["run"]
    assert final.status_code == 200 and run["status"] == "completed" and run["error_summary"] is None
    assert run["record_count"] == len(records) == 8 and run["finding_count"] == 6 and run["error_count"] == 0
    assert run["started_at"] == "2026-03-01T12:00:00.000Z" and run["duration_ms"] == 10_000

    counts, observations = query(api, run_id)
    assert (counts.sightings, counts.unique_certificates, counts.duplicate_observations, counts.repeats_within_file) == (6, 3, 3, 1)
    pfx = [o for o in observations if o["filename"] == "dup.pfx"]
    assert len(pfx) == 4 and [o["entry_ordinal"] for o in pfx] == [0, 1, 2, 3] and all(o["chain_index"] is None for o in pfx)
    assert sorted(o["sha256"] for o in pfx) == sorted(pfxgen.fp(d) for d in (LEAF, INTER, INTER, ROOT_CERT))
    assert [r["status"] for r in api.client.get("/api/runs").json()["runs"]] == ["completed"]


def test_no_key_or_certificate_bytes_reach_the_database_through_the_api(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    agent.scan_and_report(tree)
    with api.connect() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    raw = open(api.db_path, "rb").read()
    windows = set()
    for blob in (pfxgen.private_key_der(), LEAF, INTER, pfxgen.plain_with_key(extra_ca=(INTER, INTER, ROOT_CERT))):
        windows |= {blob[i:i + 40] for i in range(0, len(blob) - 40, 7)}
    for pem in pemgen.private_key_pems().values():
        windows |= {w.encode() for w in pemgen.canary_windows(pemgen.key_body_text(pem), 40, 9)}
    assert [w for w in windows if w in raw] == [] and pfxgen.fp(LEAF).encode() in raw


def test_replaying_every_batch_gives_the_same_result(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    once, twice = new_run(api, tree), new_run(api, tree)
    a, b = api.agent(agent_id="a"), api.agent(agent_id="b")
    a.claim(once)
    b.claim(twice)
    records, scan_summary = run_scan(tree)
    first = a.upload_records(records, batch_size=3)
    for start in range(0, len(records), 3):                                            # the retry storm: every batch twice more
        items = [[start + i, r] for i, r in enumerate(records[start:start + 3])]
        b.upload(items)
        replay = b.upload(items).json()
        assert replay["accepted"] == 0 and replay["duplicates"] == len(items) and replay["conflicts"] == []
        b.upload(items)
    assert all(u.status_code == 200 for u in first)
    runs = [x.finish(summary=scan_summary).json()["run"] for x in (a, b)]
    assert [r["status"] for r in runs] == ["completed", "completed"]
    assert {k: runs[0][k] for k in ("record_count", "finding_count", "rejected_count", "error_count")} == \
           {k: runs[1][k] for k in ("record_count", "finding_count", "rejected_count", "error_count")}
    assert query(api, once)[0].sightings == query(api, twice)[0].sightings == 6


def test_a_conflicting_upload_makes_the_run_partial(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    records, scan_summary = run_scan(tree)
    agent.upload_records(records, batch_size=4)
    contradiction = agent.upload([[0, ok_record(r"C:\somewhere\else.pem", n=99)]]).json()
    assert contradiction["conflicts"] == [0] and contradiction["accepted"] == 0
    run = agent.finish(summary=scan_summary).json()["run"]
    assert run["status"] == "partial" and run["error_summary"] == "seq_conflicts:1" and run["rejected_count"] == 0
    assert run["record_count"] == len(records)


def test_an_unreadable_file_makes_the_run_partial_not_failed(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    locked = put(tree, "app/locked.pem", pemgen.pem_encode(LEAF))
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    with exclusive_lock(locked):
        _, scan_summary, final = agent.scan_and_report(tree)
    run = final.json()["run"]
    assert scan_summary["complete"] is True and run["status"] == "partial"
    assert run["error_summary"] == "file_errors:1" and run["error_count"] == 1


def test_a_cancelled_scan_ends_partial(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    asked = {"calls": 0}

    def should_stop():
        asked["calls"] += 1
        if asked["calls"] == CANCEL_AT:
            api.cancel(run_id)                                                          # the user clicks Cancel mid-scan
        return agent.heartbeat().json()["cancel_requested"] if asked["calls"] > CANCEL_AT else False

    records, scan_summary = run_scan(tree, should_stop=should_stop)
    assert scan_summary["stop_reason"] == "cancelled" and 0 < len(records) < 8
    assert all(u.status_code == 200 for u in agent.upload_records(records))
    run = agent.finish(summary=scan_summary).json()["run"]
    assert run["status"] == "partial" and run["stop_reason"] == "cancelled" and run["error_summary"] == "stopped_cancelled"
    assert run["record_count"] == len(records) and run["cancel_requested"] is True


def test_cancelling_before_the_scan_found_anything_is_partial_for_both_paths(tmp_path):
    """Cancellation ends as partial even when nothing was stored: whether the agent stops on request or the backend enforces it."""
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    cooperative_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(cooperative_id)
    api.cancel(cooperative_id)
    assert agent.heartbeat().json()["cancel_requested"] is True
    records, scan_summary = run_scan(tree, should_stop=lambda: True)               # the scanner honours the request at once
    assert records == [] and scan_summary["stop_reason"] == "cancelled"
    run = agent.finish(summary=scan_summary).json()["run"]
    assert (run["status"], run["stop_reason"], run["record_count"]) == ("partial", "cancelled", 0)
    assert run["error_summary"] == "stopped_cancelled, roots_not_scanned:1"

    forced_id = new_run(api, tree)
    silent = api.agent(agent_id="b")
    silent.claim(forced_id)
    api.cancel(forced_id)
    api.clock.advance(61)
    sweep_once(api.app)
    forced = api.get(forced_id)
    assert (forced["status"], forced["stop_reason"], forced["record_count"]) == ("partial", "cancelled", 0)


def test_an_agent_that_vanishes_leaves_its_evidence_and_a_partial_run(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    records, _ = run_scan(tree)
    agent.upload_records(records[:5], batch_size=2)
    api.clock.advance(96)                                                                # the agent never comes back
    assert sweep_once(api.app) == 1
    run = api.get(run_id)
    assert (run["status"], run["stop_reason"], run["error_summary"], run["record_count"]) == ("partial", "agent_lost", "agent_lost", 5)
    assert agent.finish().status_code == 409 and query(api, run_id)[0].observations == 5


def test_an_agent_that_reports_a_fatal_failure_fails_the_run(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    agent = api.agent()
    agent.claim(run_id)
    records, _ = run_scan(tree)
    agent.upload_records(records[:3])
    run = agent.finish(outcome="failed", fatal_code="scan_crashed").json()["run"]
    assert run["status"] == "failed" and run["error_summary"] == "scan_crashed" and run["record_count"] == 3


def test_two_agents_cannot_interfere_with_each_others_runs(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    first_id, second_id = new_run(api, tree), new_run(api, tree)
    first, second, intruder = api.agent(agent_id="a-1"), api.agent(agent_id="a-2"), api.agent(agent_id="evil")
    first.claim(first_id)
    second.claim(second_id)
    assert intruder.claim(first_id).status_code == 409
    for call in (lambda: intruder.heartbeat(run_id=first_id, token="f" * 32), lambda: intruder.upload([[0, ok_record(n=1)]], run_id=first_id, token="f" * 32),
                 lambda: intruder.finish(run_id=first_id, token="f" * 32), lambda: second.heartbeat(run_id=first_id),
                 lambda: second.upload([[0, ok_record(n=1)]], run_id=first_id), lambda: second.finish(run_id=first_id)):
        assert call().status_code == 403
    assert first.upload([[0, ok_record(n=1)]]).status_code == 200 and query(api, second_id)[0].observations == 0
    assert api.get(first_id)["host_id"] == "a-1" and api.get(second_id)["host_id"] == "a-2"


# =========================================================================== real concurrency: many requests in flight
def hammer(app, calls):
    """Send all calls at once through the ASGI app: sync endpoints run in worker threads, each with its own connection."""
    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=BASE_URL) as client:
            return await asyncio.gather(*(client.request(method, url, **kwargs) for method, url, kwargs in calls))
    return asyncio.run(go())


def claim_call(run_id, agent_id):
    return ("POST", f"/api/runs/{run_id}/claim", {"json": {"agent_id": agent_id, "hostname": f"HOST-{agent_id}"}})


def test_concurrent_claims_have_exactly_one_winner(tmp_path):
    api = make_api(tmp_path)
    run_id = api.create()["run_id"]
    responses = hammer(api.app, [claim_call(run_id, f"agent-{i}") for i in range(16)])
    winners = [r for r in responses if r.status_code == 200]
    losers = [r for r in responses if r.status_code != 200]
    assert len(winners) == 1 and len(losers) == 15
    assert {r.status_code for r in losers} == {409} and {r.json()["error"]["code"] for r in losers} == {"run_not_claimable"}
    assert not any("lease_token" in r.text for r in losers)
    token = winners[0].json()["lease_token"]
    with api.connect() as conn:
        row = conn.execute("SELECT lease_hash, host_id, status FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1               # only the winner was registered
    assert row["lease_hash"] == hashlib.sha256(token.encode()).hexdigest() and row["status"] == "running"
    assert row["host_id"] == winners[0].json()["run"]["host_id"]
    heartbeat = hammer(api.app, [("POST", f"/api/runs/{run_id}/heartbeat", {"headers": {TOKEN_HEADER: token}})])
    assert heartbeat[0].status_code == 200


def test_concurrent_claims_across_several_runs_give_each_run_one_owner(tmp_path):
    api = make_api(tmp_path)
    run_ids = [api.create()["run_id"] for _ in range(4)]
    calls = [claim_call(run_id, f"agent-{run_id[:4]}-{i}") for run_id in run_ids for i in range(6)]
    responses = hammer(api.app, calls)
    by_run = {run_id: [r for (_, url, _), r in zip(calls, responses) if f"/{run_id}/" in url] for run_id in run_ids}
    assert all(sum(r.status_code == 200 for r in rs) == 1 for rs in by_run.values())
    tokens = [r.json()["lease_token"] for rs in by_run.values() for r in rs if r.status_code == 200]
    assert len(set(tokens)) == 4
    with api.connect() as conn:
        assert conn.execute("SELECT COUNT(DISTINCT lease_hash) FROM runs WHERE status = 'running'").fetchone()[0] == 4


def test_a_concurrent_retry_storm_stores_each_record_once(tmp_path):
    api = make_api(tmp_path)
    run_id = api.create()["run_id"]
    agent = api.agent()
    agent.claim(run_id)
    items = [[i, ok_record(rf"C:\app\{i}.pem", n=i + 1)] for i in range(20)]
    responses = hammer(api.app, [("POST", f"/api/runs/{run_id}/observations", {"json": {"items": items}, "headers": agent.headers()})
                                 for _ in range(10)])
    assert all(r.status_code == 200 for r in responses)
    assert sorted(r.json()["accepted"] for r in responses) == [0] * 9 + [20]            # one request stored it, the rest were replays
    assert sum(r.json()["duplicates"] for r in responses) == 9 * 20 and all(r.json()["conflicts"] == [] for r in responses)
    run = api.get(run_id)
    assert (run["record_count"], run["finding_count"]) == (20, 20) and query(api, run_id)[0].observations == 20


def test_concurrent_overlapping_batches_never_double_count(tmp_path):
    api = make_api(tmp_path)
    run_id = api.create()["run_id"]
    agent = api.agent()
    agent.claim(run_id)
    records = [ok_record(rf"C:\app\{i}.pem", n=i + 1) for i in range(30)]
    windows = [(0, 20), (10, 30), (5, 25), (0, 30), (15, 30)]
    calls = [("POST", f"/api/runs/{run_id}/observations",
              {"json": {"items": [[i, records[i]] for i in range(a, b)]}, "headers": agent.headers()}) for a, b in windows]
    responses = hammer(api.app, calls)
    assert all(r.status_code == 200 for r in responses)
    assert sum(r.json()["accepted"] for r in responses) == 30
    assert sum(r.json()["accepted"] + r.json()["duplicates"] for r in responses) == sum(b - a for a, b in windows)
    assert query(api, run_id)[0].observations == 30 and api.get(run_id)["record_count"] == 30


@pytest.mark.parametrize("round_number", range(4))
def test_finish_and_cancel_racing_always_leave_one_consistent_state(tmp_path, round_number):
    api = make_api(tmp_path)
    run_id = api.create()["run_id"]
    agent = api.agent()
    agent.claim(run_id)
    agent.upload([[0, ok_record(n=1)]])
    calls = [("POST", f"/api/runs/{run_id}/finish", {"json": {"outcome": "finished", "summary": summary(1)}, "headers": agent.headers()}),
             ("POST", f"/api/runs/{run_id}/cancel", {}), ("POST", f"/api/runs/{run_id}/cancel", {}),
             ("POST", f"/api/runs/{run_id}/heartbeat", {"headers": agent.headers()})]
    finish, cancel_a, cancel_b, beat = hammer(api.app, calls)
    run = api.get(run_id)
    assert finish.status_code == 200 and run["status"] == "completed"                    # the agent's clean finish always wins here
    assert cancel_a.status_code == cancel_b.status_code and cancel_a.status_code in (200, 409)
    assert (run["cancel_requested"], cancel_a.status_code) in ((True, 200), (False, 409))
    assert beat.status_code in (200, 409)
    assert not any(r.status_code >= 500 for r in (finish, cancel_a, cancel_b, beat))


def test_claim_and_cancel_racing_on_a_queued_run_never_mix_outcomes(tmp_path):
    for _ in range(4):
        api = make_api(tmp_path, name=f"race-{_}.db")
        run_id = api.create()["run_id"]
        claim, cancel = hammer(api.app, [claim_call(run_id, "agent"), ("POST", f"/api/runs/{run_id}/cancel", {})])
        run = api.get(run_id)
        assert cancel.status_code == 200
        if claim.status_code == 200:                                                       # claimed first, then asked to stop
            assert (run["status"], run["cancel_requested"]) == ("running", True)
        else:                                                                              # cancelled first: never claimable
            assert claim.status_code == 409 and (run["status"], run["stop_reason"]) == ("failed", "cancelled")


def test_many_agents_working_many_runs_at_once(tmp_path):
    api = make_api(tmp_path)
    run_ids = [api.create()["run_id"] for _ in range(5)]
    claims = hammer(api.app, [claim_call(rid, f"agent-{i}") for i, rid in enumerate(run_ids)])
    assert all(c.status_code == 200 for c in claims)
    tokens = {rid: c.json()["lease_token"] for rid, c in zip(run_ids, claims)}
    calls = []
    for n, rid in enumerate(run_ids):
        items = [[i, ok_record(rf"C:\r{n}\{i}.pem", n=n * 100 + i + 1)] for i in range(10)]
        calls.append(("POST", f"/api/runs/{rid}/observations", {"json": {"items": items}, "headers": {TOKEN_HEADER: tokens[rid]}}))
        calls.append(("POST", f"/api/runs/{rid}/heartbeat", {"headers": {TOKEN_HEADER: tokens[rid]}}))
    responses = hammer(api.app, calls)
    assert all(r.status_code == 200 for r in responses)
    finishes = hammer(api.app, [("POST", f"/api/runs/{rid}/finish", {"json": {"outcome": "finished", "summary": summary(10)},
                                                                       "headers": {TOKEN_HEADER: tokens[rid]}}) for rid in run_ids])
    assert [f.json()["run"]["status"] for f in finishes] == ["completed"] * 5
    assert [f.json()["run"]["record_count"] for f in finishes] == [10] * 5
    with api.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM fs_observations").fetchone()[0] == 50
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok" and conn.execute("PRAGMA foreign_key_check").fetchall() == []
