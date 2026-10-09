"""Helpers for the report-endpoint tests: seed runs straight through the real ingestion code, and compare whole databases."""
import reportfx
from backend import fs_ingest, runs
from ingestfx import at, dir_error, summary
from apifx import START

RUN_SCOPED = ("fs/summary", "fs/observations", "fs/certificates", "issues")
GLOBAL_URLS = ("/api/meta", "/api/dashboard", "/api/runs/stats")


def run_scoped_urls(run_id):
    return [f"/api/runs/{run_id}/{tail}" for tail in RUN_SCOPED]


def all_report_urls(run_id):
    return [*GLOBAL_URLS, *run_scoped_urls(run_id), "/api/certificates/" + "0" * 63 + "1"]


def seed(api, records=None, *, state="completed", config=None, errors=(), start=0):
    """Create a filesystem run in the API's database and bring it to `state`: running, completed, partial or failed.

    'partial' is a normal finish that reports a directory-level error; 'failed' is a fatal agent failure.
    """
    records = reportfx.build_records() if records is None else records
    conn = api.connect()
    try:
        run_id = runs.create_run(conn, "filesystem", "manual", now=START, config=config)
        runs.start_run(conn, run_id, now=at(1))
        if records:
            reportfx.load(conn, records, run_id, start=start)
        if state == "running":
            return run_id
        if state == "failed":
            fs_ingest.finalize_fs_run(conn, run_id, now=at(10), outcome="failed", fatal_code="boom")
            return run_id
        extra = list(errors) + ([dir_error()] if state == "partial" else [])
        fs_ingest.finalize_fs_run(conn, run_id, now=at(10), summary=summary(
            len(records), roots=((reportfx.ROOT_C, "scanned"), (reportfx.ROOT_D, "scanned")), errors=extra))
        return run_id
    finally:
        conn.close()


def dump(api):
    """Every row of every table, for before/after comparisons (reads must change nothing)."""
    conn = api.connect()
    try:
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        return {name: sorted((tuple(row) for row in conn.execute(f"SELECT * FROM {name}")), key=repr) for name in names}
    finally:
        conn.close()
