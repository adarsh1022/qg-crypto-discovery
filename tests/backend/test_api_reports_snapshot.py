"""A report request is ONE consistent snapshot even while another connection commits in the middle of it.

The request runs in its own thread and is paused (by an Event, not a sleep) right before a chosen statement; while it is
paused, the test commits new data from the test thread; then the request is released. The response must show only the
state from before the commit, as one whole, and the next request must show the new state. Connections and transactions
are checked at the end.
"""
import sqlite3
import threading

import pytest

import reportfx
from backend import db, fs_ingest
from ingestfx import at
from reportapifx import seed

WAIT = 20                                                      # seconds before a stuck test gives up (never a pacing delay)


class Gate:
    def __init__(self):
        self.marker = None                                     # pause before the first statement containing this text
        self.fired = False
        self.reached, self.proceed = threading.Event(), threading.Event()
        self.owner = threading.get_ident()                     # the test thread is never paused
        self.Connection = None


@pytest.fixture
def gate(monkeypatch):
    gate = Gate()

    class Watched(sqlite3.Connection):
        instances = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.was_closed, self.open_transaction_at_close = False, None
            self.thread = threading.get_ident()
            Watched.instances.append(self)

        def execute(self, sql, *args, **kwargs):
            if gate.marker and not gate.fired and threading.get_ident() != gate.owner and gate.marker in sql:
                gate.fired = True
                gate.reached.set()
                if not gate.proceed.wait(WAIT):
                    raise RuntimeError("the test never released the paused request")
            return super().execute(sql, *args, **kwargs)

        def close(self):
            self.open_transaction_at_close = self.in_transaction
            self.was_closed = True
            super().close()

    real = sqlite3.connect
    monkeypatch.setattr(db.sqlite3, "connect", lambda *a, **k: real(*a, factory=Watched, **k))
    Watched.instances.clear()
    gate.Connection = Watched
    return gate


def write(api, work):
    conn = api.connect()
    try:
        return work(conn)
    finally:
        conn.close()


def get_during_commit(api, gate, url, marker, commit):
    """GET `url`; pause the request right before the statement containing `marker`; run `commit()` meanwhile; release it."""
    gate.marker, gate.fired = marker, False
    gate.reached.clear()
    gate.proceed.clear()
    outcome = {}

    def request():
        try:
            outcome["response"] = api.client.get(url)
        except BaseException as exc:                           # noqa: BLE001 - reported by the test thread
            outcome["error"] = exc
    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    try:
        assert gate.reached.wait(WAIT), "the request never reached the statement the writer was meant to interrupt"
        commit()                                               # committed while the request holds its snapshot open
    finally:
        gate.proceed.set()
        worker.join(WAIT)
    gate.marker = None
    assert not worker.is_alive() and "error" not in outcome, outcome
    return outcome["response"]


def assert_cleaned_up(gate):
    instances = gate.Connection.instances
    requests = [c for c in instances if c.thread != gate.owner]
    assert requests, "the report request opened no connection of its own"
    assert all(c.was_closed for c in instances), "a connection was left open"
    assert not [c for c in requests if c.open_transaction_at_close], "a request connection was closed with its transaction still open"


def lock_free(api):
    """No lock is left behind: a writer that may not wait at all can commit."""
    writer = db.connect(api.db_path, busy_timeout_ms=0)
    try:
        with db.transaction(writer):
            writer.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('lock-check', '1')")
    finally:
        writer.close()


def add_rejected(conn, run_id, seqs):
    record = dict(reportfx.build_records()[0], sha256="not-a-fingerprint")
    result = fs_ingest.ingest_fs_batch(conn, run_id, [(seq, record) for seq in seqs], now=at(3))
    assert len(result.rejected) == len(seqs)


# =========================================================================== one scenario per kind of response
def test_the_observation_page_and_its_total_describe_the_same_snapshot(api, gate):
    """The frontier already keeps late ROWS out of the page; what only the snapshot can freeze is the stored entry_ordinal,
    which a late row with a LOWER sequence number in the same file renumbers. The page must show the old numbering."""
    records = reportfx.build_records()
    bundle = r"C:\s\b.pfx"
    first = [reportfx.pfx(bundle, 3, r"C:\s"), reportfx.pfx(bundle, 4, r"C:\s")] + records[:18]
    run_id = seed(api, first, state="running", start=100)
    url = f"/api/runs/{run_id}/fs/observations?limit=500"
    late = [reportfx.pfx(bundle, 9, r"C:\s")] + records[20:30]
    response = get_during_commit(api, gate, url, "LIMIT :limit",             # paused after the total, before the page
                                 lambda: write(api, lambda c: reportfx.load(c, late, run_id, start=5)))
    body = response.json()
    assert response.status_code == 200
    assert body["total"] == len(body["items"]) == 20 and body["frontier"] == 20                # not 31 items under a total of 20
    assert [i["seq"] for i in body["items"]] == list(range(100, 120))
    assert [i["entry_ordinal"] for i in body["items"] if i["path"] == bundle] == [0, 1]       # the numbering from before the commit
    after = api.client.get(url).json()
    assert after["total"] == len(after["items"]) == 31 and after["frontier"] > body["frontier"]
    assert [i["entry_ordinal"] for i in after["items"] if i["path"] == bundle] == [0, 1, 2]     # now including the late, lower-seq entry
    assert [i["seq"] for i in after["items"] if i["path"] == bundle] == [5, 100, 101]
    assert_cleaned_up(gate)
    lock_free(api)


def test_the_unique_view_page_and_total_describe_the_same_snapshot(api, gate):
    """Late rows are kept out of this view by the frontier alone (nothing it shows is renumbered), so unlike the other
    scenarios this one does not depend on the snapshot; it pins that page and total still agree over HTTP."""
    records = reportfx.build_records()
    run_id = seed(api, records[:12], state="running")
    url = f"/api/runs/{run_id}/fs/certificates?limit=500"
    response = get_during_commit(api, gate, url, "LIMIT :limit",
                                 lambda: write(api, lambda c: reportfx.load(c, [reportfx.cert(r"C:\late\n.pem", 40, r"C:\late")], run_id, start=500)))
    body = response.json()
    assert body["total"] == len(body["items"]) == len(reportfx.unique(records[:12]))
    after = api.client.get(url).json()
    assert after["total"] == len(after["items"]) == body["total"] + 1
    assert_cleaned_up(gate)


def test_the_summary_is_one_snapshot_including_its_live_issue_counters(api, gate):
    records = reportfx.build_records()
    run_id = seed(api, records[:20], state="running")

    def commit():
        write(api, lambda c: reportfx.load(c, records[20:], run_id, start=20))
        write(api, lambda c: add_rejected(c, run_id, [900, 901]))

    response = get_during_commit(api, gate, f"/api/runs/{run_id}/fs/summary", "JOIN certificates AS c ON c.sha256 = o.sha256 WHERE", commit)
    body = response.json()
    oracle = reportfx.summary_oracle(records[:20], api.clock())
    assert response.status_code == 200
    assert body["totals"] == oracle["totals"] and body["frontier"] == 20
    assert body["issues"]["rejected"] == 0                                                    # the live counters belong to the same snapshot
    assert body["algorithms"] == oracle["algorithms"] and body["locations"]["directories"] == oracle["locations"]["directories"]
    after = api.client.get(f"/api/runs/{run_id}/fs/summary").json()
    assert after["totals"]["records"] == len(records) and after["issues"]["rejected"] == 2
    assert_cleaned_up(gate)
    lock_free(api)


def test_the_dashboard_never_mixes_a_run_that_finished_during_the_request(api, gate):
    records = reportfx.build_records()
    older = seed(api, records[:10])
    newer = []
    response = get_during_commit(api, gate, "/api/dashboard", "FROM runs ORDER BY run_number DESC LIMIT 1",     # before the very first statement
                                 lambda: newer.append(seed(api, records[:15])))
    body = response.json()
    assert response.status_code == 200 and newer
    assert body["latest_run"]["run_id"] == body["latest_terminal_fs_run"]["run_id"] == body["summary"]["run"]["run_id"] == older
    assert body["summary"]["totals"]["records"] == 10
    assert body["runs_by_status"] == {"queued": 0, "running": 0, "completed": 1, "partial": 0, "failed": 0}
    assert [r["run_id"] for r in body["recent_runs"]] == [older]
    after = api.client.get("/api/dashboard").json()
    assert after["latest_run"]["run_id"] == after["summary"]["run"]["run_id"] == newer[0]
    assert after["runs_by_status"]["completed"] == 2 and [r["run_id"] for r in after["recent_runs"]] == [newer[0], older]
    assert_cleaned_up(gate)
    lock_free(api)


def test_run_statistics_are_one_snapshot_across_counts_and_series(api, gate):
    records = reportfx.build_records()
    first = seed(api, records[:6])
    response = get_during_commit(api, gate, "/api/runs/stats", "GROUP BY type, status",
                                 lambda: seed(api, records[:8]))                              # paused before the counts, while the second run is added
    body = response.json()
    assert sum(g["count"] for g in body["by_type_status"]) == len(body["series"]) == 1 and body["series"][0]["run_id"] == first
    after = api.client.get("/api/runs/stats").json()
    assert sum(g["count"] for g in after["by_type_status"]) == len(after["series"]) == 2
    assert_cleaned_up(gate)


def test_the_issue_page_and_its_total_describe_the_same_snapshot(api, gate):
    records = reportfx.build_records()
    run_id = seed(api, records[:5], state="running")
    write(api, lambda c: add_rejected(c, run_id, [900, 901, 902]))
    url = f"/api/runs/{run_id}/issues?limit=500"
    response = get_during_commit(api, gate, url, "SELECT source, kind, code, path, seq",       # after the count, before the page
                                 lambda: write(api, lambda c: add_rejected(c, run_id, [910, 911])))
    body = response.json()
    assert body["total"] == len(body["items"]) == 3 and [i["seq"] for i in body["items"]] == [900, 901, 902]
    after = api.client.get(url).json()
    assert after["total"] == len(after["items"]) == 5
    assert_cleaned_up(gate)
    lock_free(api)


def test_certificate_detail_totals_and_path_lists_agree_while_the_run_grows(api, gate):
    from ingestfx import sha
    records = reportfx.build_records()
    run_id = seed(api, [reportfx.cert(r"C:\a\one.pem", 1, r"C:\a")] + records[1:4], state="running")
    url = f"/api/certificates/{sha(1)}"

    def commit():                                                          # the same certificate at a new path, and in a new run
        write(api, lambda c: reportfx.load(c, [reportfx.cert(r"C:\a\two.pem", 1, r"C:\a")], run_id, start=500))
        seed(api, records[:3])
    response = get_during_commit(api, gate, url, "SELECT DISTINCT path", commit)                  # after the totals, before the path list
    body = response.json()
    assert response.status_code == 200 and body["runs_total"] == len(body["runs"]) == 1 and body["sightings_total"] == 1
    entry = body["runs"][0]
    assert (entry["run_id"], entry["sightings"], entry["paths_count"], entry["paths"]) == (run_id, 1, 1, [r"C:\a\one.pem"])
    after = api.client.get(url).json()
    assert after["runs_total"] == len(after["runs"]) == 2 and after["sightings_total"] == sum(r["sightings"] for r in after["runs"]) == 3
    by_run = {r["run_id"]: r for r in after["runs"]}
    assert by_run[run_id]["paths"] == [r"C:\a\one.pem", r"C:\a\two.pem"] and by_run[run_id]["paths_count"] == 2
    assert_cleaned_up(gate)
