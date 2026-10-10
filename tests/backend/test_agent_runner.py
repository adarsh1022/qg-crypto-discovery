"""The real agent runner (client + runner + real scanner) against the real FastAPI app, in-process."""
import logging
import threading
import time

import pytest

import pfxgen
from agent.fs_scan import Scan
from agent.runner import poll_once, run_claimed
from agentfx import make_client, options
from apifx import make_api
from backend import fs_queries
from test_api_e2e import INTER, LEAF, ROOT_CERT, build_tree
from treegen import run_scan


def new_run(api, tree, **config):
    return api.create(config={"roots": [str(tree)], **config})["run_id"]


def counts(api, run_id):
    with api.connect() as conn:
        return fs_queries.fs_counts(conn, run_id)


def oracle(tree):
    return run_scan(str(tree))


class SlowScan:
    """The real scanner, but the first record only appears after `delay` seconds (a long, quiet directory walk)."""

    def __init__(self, delay, config, should_stop=None, **_):
        self._scan, self._delay = Scan(config, should_stop=should_stop), delay

    def records(self):
        time.sleep(self._delay)
        yield from self._scan.records()

    @property
    def summary(self):
        return self._scan.summary


# =========================================================================== success
def test_a_queued_run_is_claimed_scanned_uploaded_and_completed(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    client, wire = make_client(api)

    report = poll_once(client, options(batch_size=3))

    expected_records, expected_summary = oracle(tree)
    assert (report.run_id, report.outcome, report.final_status) == (run_id, "finished", "completed")
    assert report.records_sent == report.accepted == len(expected_records) == 8
    assert (report.rejected, report.conflicts, report.duplicates, report.batches) == (0, 0, 0, 3)
    run = api.get(run_id)
    assert run["status"] == "completed" and (run["record_count"], run["finding_count"], run["error_count"]) == (8, 6, 0)
    assert run["agent_summary"]["records"] == 8 and run["agent_summary"]["stop_reason"] == "completed"
    c = counts(api, run_id)
    assert (c.sightings, c.unique_certificates) == (6, 3)
    # the results are visible through the report API the browser will use
    summary = api.client.get(f"/api/runs/{run_id}/fs/summary").json()
    assert summary["run"]["run_id"] == run_id
    certs = api.client.get(f"/api/runs/{run_id}/fs/certificates").json()
    assert {item["sha256"] for item in certs["items"]} == {pfxgen.fp(d) for d in (LEAF, INTER, ROOT_CERT)}


def test_sequence_numbers_are_contiguous_across_batches(tmp_path):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    client, wire = make_client(api)
    poll_once(client, options(batch_size=3))
    seqs = [seq for items in wire.uploads() for seq, _ in items]
    assert seqs == list(range(8))


def test_nothing_queued_does_nothing(tmp_path):
    api = make_api(tmp_path)
    client, wire = make_client(api)
    assert poll_once(client, options()) is None
    assert [c[1] for c in wire.calls] == ["/api/runs"]


class QuietTlsScan:
    """A TLS scan stand-in that finds nothing, so this test never probes the machine's real listeners."""

    def __init__(self, config, should_stop=None, **_):
        pass

    def records(self):
        return iter(())

    summary = {"stop_reason": "completed", "enumeration": "ok", "complete": True, "listeners_found": 0, "port_filtered": 0,
               "policy_skipped": 0, "targets_planned": 0, "targets_probed": 0, "records": 0, "handshakes_completed": 0,
               "targets_truncated": False, "records_by_outcome": {}, "errors": [], "errors_total": 0, "elapsed_seconds": 0.0}


def test_runs_are_taken_oldest_first_whatever_their_type(tmp_path):
    # Changed with TLS scanning (M3): this test used to assert that the agent ignored TLS runs. The ordering assertions are the
    # same; a TLS run now takes part in the queue like any other run.
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    tls_first = api.create("tls", config={})["run_id"]
    first = new_run(api, tree)
    tls_second = api.create("tls", config={})["run_id"]
    second = new_run(api, tree)
    client, _ = make_client(api)
    taken = [poll_once(client, options(), tls_scan_factory=QuietTlsScan).run_id for _ in range(4)]
    assert taken == [tls_first, first, tls_second, second]
    assert poll_once(client, options()) is None
    assert [api.get(r)["status"] for r in taken] == ["completed"] * 4


def test_a_run_lost_to_another_agent_is_skipped_for_the_next_one(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    first, second = new_run(api, tree), new_run(api, tree)
    rival = api.agent(agent_id="rival")

    def steal_after_listing(wire, method, path, body, response):
        if method == "GET" and not wire.paths("/claim"):
            assert rival.claim(first).status_code == 200

    client, _ = make_client(api, after=steal_after_listing)
    report = poll_once(client, options())
    assert report.run_id == second and report.outcome == "finished"
    assert api.get(first)["status"] == "running" and api.get(second)["status"] == "completed"


# =========================================================================== limits
def test_batches_respect_the_servers_item_limit(tmp_path):
    api = make_api(tmp_path, max_batch_items=2)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    client, wire = make_client(api)
    report = poll_once(client, options(batch_size=500))
    assert report.outcome == "finished" and report.accepted == 8
    assert [len(items) for items in wire.uploads()] == [2, 2, 2, 2]


def test_batches_respect_the_servers_body_limit(tmp_path):
    api = make_api(tmp_path, max_body_bytes=8000)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    client, wire = make_client(api)
    report = poll_once(client, options(batch_size=500))
    assert report.outcome == "finished" and report.accepted == 8 and report.rejected == 0
    sizes = [len(c[2]) for c in wire.paths("/observations")]
    assert len(sizes) > 1 and max(sizes) <= 8000
    assert api.get(run_id)["status"] == "completed"


def test_an_empty_scan_still_finishes_cleanly(tmp_path):
    api = make_api(tmp_path)
    (tmp_path / "empty").mkdir()
    run_id = new_run(api, tmp_path / "empty")
    client, wire = make_client(api)
    report = poll_once(client, options())
    assert report.outcome == "finished" and report.records_sent == 0 and wire.uploads() == []
    assert api.get(run_id)["status"] == "completed"


# =========================================================================== bad configuration
@pytest.mark.parametrize("config", [
    {"roots": ["relative\\dir"]},
    {"roots": ["\\\\server\\share\\x"]},
    {"roots": ["C:\\"], "exclude_paths": ["relative"]},                 # the backend accepts these; only the agent can judge them
    {"roots": ["C:\\"], "exclude_dir_names": ["a\\b"]},
])
def test_an_invalid_config_fails_the_run_without_scanning(tmp_path, config):
    api = make_api(tmp_path)
    run_id = api.create(config=config)["run_id"]
    client, wire = make_client(api)
    report = poll_once(client, options())
    assert (report.outcome, report.detail) == ("failed", "invalid_config")
    run = api.get(run_id)
    assert run["status"] == "failed" and run["record_count"] == 0
    assert wire.uploads() == []


# =========================================================================== cancellation
def test_cancellation_stops_the_scan_and_ends_the_run_partial(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    for i in range(20):
        (tmp_path / "tree" / "more").mkdir(exist_ok=True)
        (tmp_path / "tree" / "more" / f"f{i}.txt").write_bytes(b"x")
    run_id = new_run(api, tree)

    def cancel_after_first_upload(wire, method, path, body, response):
        if path.endswith("/observations") and len(wire.paths("/observations")) == 1:
            assert api.cancel(run_id).status_code == 200

    client, wire = make_client(api, after=cancel_after_first_upload)
    report = poll_once(client, options(batch_size=1))
    assert report.cancelled and report.outcome == "finished" and report.final_status == "partial"
    run = api.get(run_id)
    assert run["status"] == "partial" and run["cancel_requested"] and run["agent_summary"]["stop_reason"] == "cancelled"
    assert 0 < run["record_count"] < 8                                   # stopped early; what was found is kept


def test_cancellation_is_noticed_by_a_heartbeat_during_a_quiet_scan(tmp_path):
    api = make_api(tmp_path, heartbeat_interval_s=0.05)
    run_id = new_run(api, build_tree(tmp_path / "tree"))

    def cancel_on_first_heartbeat(wire, method, path, body, response):
        if path.endswith("/heartbeat"):
            api.cancel(run_id)

    client, wire = make_client(api, after=cancel_on_first_heartbeat)
    factory = lambda config, should_stop=None: SlowScan(0.6, config, should_stop)
    report = poll_once(client, options(), scan_factory=factory)
    assert report.cancelled and report.outcome == "finished" and report.records_sent == 0
    assert api.get(run_id)["status"] == "partial"


# =========================================================================== heartbeats
def test_heartbeats_keep_flowing_while_the_scan_is_quiet(tmp_path):
    api = make_api(tmp_path, heartbeat_interval_s=0.05)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    client, wire = make_client(api)
    factory = lambda config, should_stop=None: SlowScan(0.5, config, should_stop)
    report = poll_once(client, options(), scan_factory=factory)
    assert report.outcome == "finished" and report.accepted == 8
    assert len(wire.paths("/heartbeat")) >= 3
    assert api.get(run_id)["status"] == "completed"


# =========================================================================== network failures
def test_a_lost_response_is_replayed_without_duplicating_evidence(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    failed = []

    def drop_response_once(wire, method, path, body, response):
        if path.endswith("/observations") and not failed:
            failed.append(path)
            raise ConnectionResetError("response lost")                # the backend stored the batch; the agent never heard

    client, wire = make_client(api, after=drop_response_once)
    report = poll_once(client, options(batch_size=3))
    assert report.outcome == "finished"
    assert (report.accepted, report.duplicates) == (5, 3)              # the replayed first batch is recognised as already stored
    assert len(wire.paths("/observations")) == 4                       # 3 batches + 1 replay
    run = api.get(run_id)
    assert run["status"] == "completed" and (run["record_count"], run["finding_count"]) == (8, 6)
    c = counts(api, run_id)
    assert (c.sightings, c.unique_certificates) == (6, 3)


def test_a_request_that_never_arrived_is_retried(tmp_path):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    failures = []

    def refuse_twice(wire, method, path, body):
        if path.endswith("/observations") and len(failures) < 2:
            failures.append(1)
            raise ConnectionRefusedError("down")

    client, wire = make_client(api, before=refuse_twice)
    report = poll_once(client, options(batch_size=500, upload_retries=3))
    assert report.outcome == "finished" and report.accepted == 8 and len(failures) == 2
    assert api.get(run_id)["status"] == "completed"


def test_a_backend_that_stays_down_ends_the_attempt_quietly_and_leaves_the_run_to_expire(tmp_path, caplog):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))

    def down_after_claim(wire, method, path, body):
        if path.endswith("/observations") or path.endswith("/finish"):
            raise ConnectionRefusedError("down")

    client, wire = make_client(api, before=down_after_claim)
    with caplog.at_level(logging.DEBUG):
        report = poll_once(client, options(upload_retries=2))
    assert (report.outcome, report.detail) == ("unreachable", "backend_unreachable")
    assert api.get(run_id)["status"] == "running"                      # the backend's own timeout will resolve it
    assert api.get(run_id)["record_count"] == 0


# =========================================================================== lease loss
def test_a_lost_lease_stops_the_agent_without_hammering_the_backend(tmp_path):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))

    def lease_runs_out(wire, method, path, body):
        if path.endswith("/observations") and not wire.paths("/observations"):
            api.clock.advance(10_000)                                  # no sign of life for far longer than the timeout

    client, wire = make_client(api, before=lease_runs_out)
    report = poll_once(client, options(batch_size=2))
    assert report.outcome == "lost"
    assert len(wire.paths("/observations")) == 1 and wire.paths("/finish") == []
    assert api.get(run_id)["status"] in ("partial", "failed")


def test_a_refused_heartbeat_marks_the_lease_lost(tmp_path):
    api = make_api(tmp_path, heartbeat_interval_s=0.05)
    run_id = new_run(api, build_tree(tmp_path / "tree"))

    def overdue(wire, method, path, body):
        if path.endswith("/heartbeat"):
            api.clock.advance(10_000)

    client, wire = make_client(api, before=overdue)
    factory = lambda config, should_stop=None: SlowScan(0.6, config, should_stop)
    report = poll_once(client, options(), scan_factory=factory)
    assert report.outcome == "lost" and wire.uploads() == [] and wire.paths("/finish") == []


# =========================================================================== shutdown and agent bugs
def test_ctrl_c_style_shutdown_fails_the_run_as_agent_stopped(tmp_path):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    run_id = new_run(api, tree)
    shutdown = threading.Event()

    def stop_after_first_upload(wire, method, path, body, response):
        if path.endswith("/observations"):
            shutdown.set()

    client, wire = make_client(api, after=stop_after_first_upload)
    report = poll_once(client, options(batch_size=1), shutdown)
    assert (report.outcome, report.detail) == ("failed", "agent_stopped")
    run = api.get(run_id)
    assert run["status"] == "failed" and run["record_count"] >= 1


def test_a_scanner_bug_fails_the_run_and_leaks_nothing(tmp_path, caplog):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))

    class Broken:
        def __init__(self, config, should_stop=None):
            pass

        def records(self):
            raise RuntimeError(f"secret path {tmp_path}")
            yield

        summary = {}

    client, wire = make_client(api)
    with caplog.at_level(logging.DEBUG):
        report = poll_once(client, options(), scan_factory=Broken)
    assert (report.outcome, report.detail) == ("failed", "agent_error")
    assert api.get(run_id)["status"] == "failed"
    assert "secret" not in caplog.text and str(tmp_path) not in caplog.text and "RuntimeError" in caplog.text


# =========================================================================== hygiene
def test_logs_never_contain_the_token_paths_or_certificate_content(tmp_path, caplog):
    api = make_api(tmp_path)
    tree = build_tree(tmp_path / "tree")
    api.create(config={"roots": ["relative"]})
    new_run(api, tree)
    tokens = []

    def note_token(wire, method, path, body, response):
        if path.endswith("/claim") and response.status_code == 200:
            tokens.append(response.json()["lease_token"])

    client, wire = make_client(api, after=note_token)
    with caplog.at_level(logging.DEBUG):
        assert poll_once(client, options()).detail == "invalid_config"
        assert poll_once(client, options()).outcome == "finished"
    assert len(tokens) == 2
    text = caplog.text
    for token in tokens:
        assert token not in text
    for sensitive in (str(tree), pfxgen.fp(LEAF), "BEGIN", "server.pem", "CN="):
        assert sensitive not in text
    assert "claimed run" in text                                       # it did log something


def test_the_token_is_only_ever_sent_as_a_header(tmp_path):
    api = make_api(tmp_path)
    new_run(api, build_tree(tmp_path / "tree"))
    seen = []

    def note(wire, method, path, body, response):
        if path.endswith("/claim") and response.status_code == 200:
            seen.append(response.json()["lease_token"])

    client, wire = make_client(api, after=note)
    poll_once(client, options())
    token = seen[0]
    assert all(token not in c[1] and token.encode() not in (c[2] or b"") for c in wire.calls)


def test_no_private_key_material_is_uploaded(tmp_path):
    api = make_api(tmp_path)
    new_run(api, build_tree(tmp_path / "tree", with_keys=True))
    client, wire = make_client(api)
    poll_once(client, options())
    sent = b"".join(c[2] or b"" for c in wire.paths("/observations"))
    assert b"PRIVATE KEY" not in sent and b"BEGIN" not in sent


def test_run_claimed_works_directly_from_a_claim_response(tmp_path):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    client, wire = make_client(api)
    agent = api.agent()
    claim = agent.claim(run_id).json()
    report = run_claimed(client, claim, options(), threading.Event())
    assert report.outcome == "finished" and api.get(run_id)["status"] == "completed"


def test_a_second_finish_after_success_is_treated_as_done(tmp_path):
    api = make_api(tmp_path)
    run_id = new_run(api, build_tree(tmp_path / "tree"))
    done = []

    def finish_twice(wire, method, path, body, response):
        if path.endswith("/finish") and not done:
            done.append(1)
            raise ConnectionResetError("response lost")                # finish was applied but the agent never heard

    client, wire = make_client(api, after=finish_twice)
    report = poll_once(client, options())
    # The agent repeats the finish; the backend answers run_already_finished with the final run, which counts as success.
    assert report.outcome == "finished" and report.final_status == "completed"
    assert len(wire.paths("/finish")) == 2 and api.get(run_id)["status"] == "completed"
