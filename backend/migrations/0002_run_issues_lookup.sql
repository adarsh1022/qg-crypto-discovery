-- Index for the "was this seq already rejected?" lookup made for every ingested record.
-- Before this, each lookup scanned all issues of the run (via idx_run_issues_run), so a run with many rejected
-- records cost O(n^2). Non-unique on purpose: agent-reported issues have no seq, and one seq may appear in
-- issues of different kinds.
CREATE INDEX idx_run_issues_kind_seq ON run_issues (run_id, kind, seq);
