-- Initial schema. Applied once, inside one transaction, by backend/db.py (which also sets user_version).
--
-- Conventions
--   * STRICT tables: a value of the wrong type (including a BLOB in a TEXT column) is an error.
--   * Only parsed, allow-listed facts are stored. There is no column for raw certificate bytes, PEM text,
--     private keys, passwords or other secrets (tests/backend/test_db_schema.py enforces that).
--   * Timestamps are ISO-8601 UTC text ending in Z, so they sort lexicographically.
--     runs.*_at carry milliseconds (...:SS.mmmZ); agent-supplied timestamps have second resolution.
--   * Booleans are INTEGER 0/1. JSON columns are TEXT checked with json_valid().
--   * Nothing is ever deleted by the application (no retention policy), so foreign keys are plain RESTRICT.

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE hosts (
    host_id       TEXT PRIMARY KEY,
    hostname      TEXT NOT NULL,
    os            TEXT,
    agent_version TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
) STRICT;

-- Schema only in Phase 2a; the scheduler arrives in Phase 2f.
CREATE TABLE schedules (
    schedule_id      TEXT PRIMARY KEY,
    run_type         TEXT NOT NULL CHECK (run_type IN ('filesystem', 'tls')),
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
    config_json      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json) AND json_type(config_json) = 'object'),
    enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    next_due_at      TEXT,
    last_run_id      TEXT,                -- informational only (no FK: avoids a runs <-> schedules cycle)
    created_at       TEXT NOT NULL
) STRICT;

CREATE TABLE runs (
    run_id       TEXT PRIMARY KEY CHECK (length(run_id) BETWEEN 8 AND 64),
    run_number   INTEGER NOT NULL UNIQUE CHECK (run_number > 0),
    type         TEXT NOT NULL CHECK (type IN ('filesystem', 'tls')),
    run_trigger  TEXT NOT NULL CHECK (run_trigger IN ('manual', 'scheduled')),
    schedule_id  TEXT REFERENCES schedules (schedule_id),
    status       TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'partial', 'failed')),
    config_json  TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(config_json) AND json_type(config_json) = 'object'),
    host_id      TEXT REFERENCES hosts (host_id),

    queued_at         TEXT NOT NULL
        CHECK (queued_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    started_at        TEXT
        CHECK (started_at IS NULL OR started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    finished_at       TEXT
        CHECK (finished_at IS NULL OR finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    last_heartbeat_at TEXT
        CHECK (last_heartbeat_at IS NULL OR last_heartbeat_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z'),
    duration_ms       INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),

    stop_reason      TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
    -- Recomputed by the backend from stored rows, never copied from the agent's own claims.
    record_count     INTEGER NOT NULL DEFAULT 0 CHECK (record_count   >= 0),
    finding_count    INTEGER NOT NULL DEFAULT 0 CHECK (finding_count  >= 0),
    rejected_count   INTEGER NOT NULL DEFAULT 0 CHECK (rejected_count >= 0),
    error_count      INTEGER NOT NULL DEFAULT 0 CHECK (error_count    >= 0),
    error_summary    TEXT,                -- fixed codes and counts only, never OS messages or paths
    agent_summary_json TEXT CHECK (agent_summary_json IS NULL OR json_valid(agent_summary_json)),

    CHECK (run_trigger = 'scheduled' OR schedule_id IS NULL),
    -- timestamps must agree with the status
    CHECK (
        (status = 'queued'  AND started_at IS NULL     AND finished_at IS NULL     AND duration_ms IS NULL)
     OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL     AND duration_ms IS NULL)
     OR (status IN ('completed', 'partial')
                            AND started_at IS NOT NULL AND finished_at IS NOT NULL AND duration_ms IS NOT NULL)
     OR (status = 'failed'  AND finished_at IS NOT NULL AND (started_at IS NULL) = (duration_ms IS NULL))
    ),
    CHECK (started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at),
    -- partial and failed runs must say why
    CHECK (status NOT IN ('partial', 'failed') OR error_summary IS NOT NULL)
) STRICT;

CREATE INDEX idx_runs_active      ON runs (status, queued_at);     -- serves "oldest queued run" and active-run lookups
CREATE INDEX idx_runs_type_status ON runs (type, status);
CREATE INDEX idx_runs_started     ON runs (started_at);

-- Defence in depth for the lifecycle (the pure state machine in backend/run_state.py is the primary rule).
CREATE TRIGGER runs_status_transition
BEFORE UPDATE OF status ON runs
WHEN OLD.status <> NEW.status AND NOT (
       (OLD.status = 'queued'  AND NEW.status IN ('running', 'failed'))
    OR (OLD.status = 'running' AND NEW.status IN ('completed', 'partial', 'failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid run status transition');
END;

CREATE TABLE run_issues (
    id     INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs (run_id),
    source TEXT NOT NULL CHECK (source IN ('agent', 'backend')),
    kind   TEXT NOT NULL,
    code   TEXT NOT NULL,
    path   TEXT,
    seq    INTEGER
) STRICT;
CREATE INDEX idx_run_issues_run ON run_issues (run_id);

-- Certificate catalog: one row per SHA-256 of the DER, intrinsic facts only.
CREATE TABLE certificates (
    sha256              TEXT PRIMARY KEY
        CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    serial_hex          TEXT NOT NULL,
    subject             TEXT NOT NULL,
    issuer              TEXT NOT NULL,
    san_json            TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(san_json) AND json_type(san_json) = 'array'),
    key_algorithm       TEXT NOT NULL,
    key_size            INTEGER CHECK (key_size IS NULL OR key_size > 0),
    key_curve           TEXT,
    signature_algorithm TEXT NOT NULL,
    not_before          TEXT NOT NULL
        CHECK (not_before GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'),
    not_after           TEXT NOT NULL
        CHECK (not_after  GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'),
    is_ca               INTEGER CHECK (is_ca IS NULL OR is_ca IN (0, 1)),
    first_seen_run      TEXT NOT NULL REFERENCES runs (run_id),
    first_seen_at       TEXT NOT NULL,
    last_seen_run       TEXT NOT NULL REFERENCES runs (run_id),
    last_seen_at        TEXT NOT NULL
) STRICT;
CREATE INDEX idx_certificates_not_after ON certificates (not_after);
CREATE INDEX idx_certificates_key       ON certificates (key_algorithm, key_size);
CREATE INDEX idx_certificates_issuer    ON certificates (issuer);

-- One row per certificate sighting, or per candidate file that yielded no certificate.
-- Deliberately NO uniqueness on (run_id, sha256) or (run_id, path, sha256): the same certificate may
-- legitimately appear several times in one file (a PKCS#12 has no chain order) and must not be collapsed.
-- (run_id, seq) is the idempotency key; seq is the agent's per-run counter.
CREATE TABLE fs_observations (
    id            INTEGER PRIMARY KEY,
    run_id        TEXT NOT NULL REFERENCES runs (run_id),
    seq           INTEGER NOT NULL CHECK (seq >= 0),
    entry_ordinal INTEGER NOT NULL CHECK (entry_ordinal >= 0),   -- n-th record for this path in the run (backend-assigned)
    path          TEXT NOT NULL,
    filename      TEXT NOT NULL,
    scan_root     TEXT NOT NULL,
    format        TEXT NOT NULL CHECK (format IN ('pem', 'der', 'pkcs12', 'unknown')),
    discovered_at TEXT NOT NULL
        CHECK (discovered_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z'),
    sha256        TEXT REFERENCES certificates (sha256),
    chain_index   INTEGER CHECK (chain_index IS NULL OR chain_index >= 0),
    chain_total   INTEGER CHECK (chain_total IS NULL OR chain_total >= 0),
    chain_role    TEXT CHECK (chain_role IS NULL OR chain_role IN ('self_signed', 'ca', 'leaf')),
    parse_status  TEXT NOT NULL CHECK (parse_status IN
        ('ok', 'malformed', 'unsupported', 'too_large', 'no_certificate', 'access_denied', 'read_error', 'skipped')),
    detail        TEXT,
    access_error  TEXT,
    evidence_confidence TEXT NOT NULL CHECK (evidence_confidence IN ('high', 'medium', 'low')),
    extension_mismatch  INTEGER NOT NULL DEFAULT 0 CHECK (extension_mismatch IN (0, 1)),
    warnings_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(warnings_json) AND json_type(warnings_json) = 'array'),
    -- state as of discovered_at; "current" posture is derived from certificates.not_after at query time
    validity_status TEXT CHECK (validity_status IS NULL OR validity_status IN ('valid', 'expiring', 'expired')),
    days_to_expiry  INTEGER,
    not_yet_valid   INTEGER CHECK (not_yet_valid IS NULL OR not_yet_valid IN (0, 1)),
    owning_process_json TEXT CHECK (owning_process_json IS NULL
        OR (json_valid(owning_process_json) AND json_type(owning_process_json) = 'object')),
    UNIQUE (run_id, seq),
    -- Phase 1 invariants, enforced again at the storage boundary
    CHECK ((parse_status = 'ok') = (sha256 IS NOT NULL)),
    CHECK ((sha256 IS NULL) = (chain_role IS NULL)),
    CHECK ((sha256 IS NULL) = (validity_status IS NULL)),
    CHECK (sha256 IS NOT NULL OR (days_to_expiry IS NULL AND not_yet_valid IS NULL)),
    CHECK (parse_status = 'ok' OR evidence_confidence = 'low'),
    CHECK (format <> 'pkcs12' OR chain_index IS NULL),
    CHECK (instr(warnings_json, 'pkcs12_integrity_not_verified') = 0 OR evidence_confidence <> 'high')
) STRICT;
CREATE INDEX idx_fs_run_sha256   ON fs_observations (run_id, sha256);
CREATE INDEX idx_fs_run_parse    ON fs_observations (run_id, parse_status);
CREATE INDEX idx_fs_run_validity ON fs_observations (run_id, validity_status);
CREATE INDEX idx_fs_run_root     ON fs_observations (run_id, scan_root);
CREATE INDEX idx_fs_run_path     ON fs_observations (run_id, path);
CREATE INDEX idx_fs_sha256       ON fs_observations (sha256);

-- One row per observed TLS connection (a reused 5-tuple is a new connection, never merged).
-- The wire fields are provisional until the TLS capture phase.
CREATE TABLE tls_observations (
    id               INTEGER PRIMARY KEY,
    run_id           TEXT NOT NULL REFERENCES runs (run_id),
    seq              INTEGER NOT NULL CHECK (seq >= 0),
    observed_at      TEXT NOT NULL
        CHECK (observed_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]*Z'),
    last_event_at    TEXT,
    direction        TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound', 'unknown')),
    transport        TEXT NOT NULL DEFAULT 'tcp' CHECK (transport IN ('tcp')),
    src_ip           TEXT NOT NULL,
    src_port         INTEGER NOT NULL CHECK (src_port BETWEEN 0 AND 65535),
    dst_ip           TEXT NOT NULL,
    dst_port         INTEGER NOT NULL CHECK (dst_port BETWEEN 0 AND 65535),
    local_ip         TEXT,                -- normalized from direction; NULL when direction is unknown
    local_port       INTEGER CHECK (local_port IS NULL OR local_port BETWEEN 0 AND 65535),
    remote_ip        TEXT,
    remote_port      INTEGER CHECK (remote_port IS NULL OR remote_port BETWEEN 0 AND 65535),
    handshake_outcome TEXT NOT NULL
        CHECK (handshake_outcome IN ('completed', 'failed', 'alert', 'incomplete', 'unknown')),
    sni              TEXT,
    tls_version      TEXT CHECK (tls_version IS NULL OR tls_version IN ('SSL3', 'TLS1.0', 'TLS1.1', 'TLS1.2', 'TLS1.3')),
    cipher_suite     TEXT,
    cipher_id        INTEGER CHECK (cipher_id IS NULL OR cipher_id BETWEEN 0 AND 65535),
    cert_visibility  TEXT NOT NULL CHECK (cert_visibility IN ('visible', 'encrypted_tls13', 'not_observed')),
    pid              INTEGER CHECK (pid IS NULL OR pid >= 0),
    process_name     TEXT,
    exe_path         TEXT,
    process_attribution TEXT NOT NULL DEFAULT 'unavailable'
        CHECK (process_attribution IN ('attributed', 'not_found', 'unavailable')),
    event_count      INTEGER NOT NULL DEFAULT 0 CHECK (event_count  >= 0),
    packet_count     INTEGER NOT NULL DEFAULT 0 CHECK (packet_count >= 0),
    event_counts_json TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(event_counts_json) AND json_type(event_counts_json) = 'object'),
    evidence_confidence TEXT NOT NULL CHECK (evidence_confidence IN ('high', 'medium', 'low')),
    warnings_json    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(warnings_json) AND json_type(warnings_json) = 'array'),
    UNIQUE (run_id, seq)
) STRICT;
CREATE INDEX idx_tls_run_remote  ON tls_observations (run_id, remote_ip, remote_port);
CREATE INDEX idx_tls_run_version ON tls_observations (run_id, tls_version);
CREATE INDEX idx_tls_run_cipher  ON tls_observations (run_id, cipher_suite);
CREATE INDEX idx_tls_run_time    ON tls_observations (run_id, observed_at);
CREATE INDEX idx_tls_run_process ON tls_observations (run_id, process_name);

-- Peer certificates of a connection, leaf first. Certificates are normalized through the catalog.
CREATE TABLE tls_peer_certificates (
    tls_observation_id INTEGER NOT NULL REFERENCES tls_observations (id),
    position           INTEGER NOT NULL CHECK (position >= 0),
    sha256             TEXT NOT NULL REFERENCES certificates (sha256),
    PRIMARY KEY (tls_observation_id, position)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_tls_peer_certificates_sha256 ON tls_peer_certificates (sha256);

-- Relationship graph. Three atomic edge kinds only; host/process -> certificate -> remote endpoint is
-- derived by the report layer from observed facts, never stored as an extra edge.
CREATE TABLE nodes (
    node_id       INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('host', 'process', 'certificate', 'endpoint')),
    node_key      TEXT NOT NULL,          -- host_id | exe path or name (never a PID) | sha256 | ip:port/transport
    label         TEXT NOT NULL,
    attrs_json    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs_json) AND json_type(attrs_json) = 'object'),
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    UNIQUE (kind, node_key)
) STRICT;

CREATE TABLE edges (
    edge_id           INTEGER PRIMARY KEY,
    src_node          INTEGER NOT NULL REFERENCES nodes (node_id),
    dst_node          INTEGER NOT NULL REFERENCES nodes (node_id),
    kind              TEXT NOT NULL CHECK (kind IN ('communicates_with', 'presented_certificate', 'stored_on')),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 1),
    run_count         INTEGER NOT NULL CHECK (run_count >= 1),
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    attrs_json        TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(attrs_json) AND json_type(attrs_json) = 'object'),
    UNIQUE (src_node, dst_node, kind),
    CHECK (src_node <> dst_node)
) STRICT;
CREATE INDEX idx_edges_dst  ON edges (dst_node);
CREATE INDEX idx_edges_kind ON edges (kind, last_seen_at);

-- Which node kinds each edge kind may connect:
--   communicates_with     host|process  -> endpoint
--   presented_certificate host|process|endpoint -> certificate
--   stored_on             certificate   -> host
CREATE TRIGGER edges_node_kinds_insert
BEFORE INSERT ON edges
WHEN NOT (
    (NEW.kind = 'communicates_with'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) IN ('host', 'process')
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'endpoint')
 OR (NEW.kind = 'presented_certificate'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) IN ('host', 'process', 'endpoint')
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'certificate')
 OR (NEW.kind = 'stored_on'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) = 'certificate'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'host')
)
BEGIN
    SELECT RAISE(ABORT, 'edge kind does not match node kinds');
END;

CREATE TRIGGER edges_node_kinds_update
BEFORE UPDATE OF src_node, dst_node, kind ON edges
WHEN NOT (
    (NEW.kind = 'communicates_with'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) IN ('host', 'process')
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'endpoint')
 OR (NEW.kind = 'presented_certificate'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) IN ('host', 'process', 'endpoint')
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'certificate')
 OR (NEW.kind = 'stored_on'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.src_node) = 'certificate'
        AND (SELECT kind FROM nodes WHERE node_id = NEW.dst_node) = 'host')
)
BEGIN
    SELECT RAISE(ABORT, 'edge kind does not match node kinds');
END;

-- Per-run contribution to an edge, so each run can render its own graph.
CREATE TABLE edge_runs (
    edge_id           INTEGER NOT NULL REFERENCES edges (edge_id),
    run_id            TEXT NOT NULL REFERENCES runs (run_id),
    observation_count INTEGER NOT NULL CHECK (observation_count >= 1),
    first_at          TEXT NOT NULL,
    last_at           TEXT NOT NULL,
    PRIMARY KEY (edge_id, run_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX idx_edge_runs_run ON edge_runs (run_id);
