-- Run ownership (lease), cancellation timestamp and an immutable run request.
--
--   lease_hash           SHA-256 of the claim token. The plaintext token is returned once, to the claiming agent, and is
--                        never stored. NULL until the run is claimed.
--   cancel_requested_at  when a running run was asked to stop (set together with cancel_requested, never changed).
--
-- Existing rows keep NULL in both columns. A run that was already "running" before this migration therefore has no
-- lease: nothing can present a matching token, so it simply ends as lost when its heartbeat goes stale.

ALTER TABLE runs ADD COLUMN lease_hash TEXT
    CHECK (lease_hash IS NULL OR (length(lease_hash) = 64 AND lease_hash NOT GLOB '*[^0-9a-f]*'));

ALTER TABLE runs ADD COLUMN cancel_requested_at TEXT
    CHECK (cancel_requested_at IS NULL OR cancel_requested_at GLOB
        '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z');

-- What was requested never changes after the run is created. (Fires only when a value actually differs: the
-- application rewrites whole rows, so an UPDATE that leaves these columns as they were must pass.)
CREATE TRIGGER runs_request_immutable
BEFORE UPDATE ON runs
WHEN NEW.run_id IS NOT OLD.run_id OR NEW.run_number IS NOT OLD.run_number OR NEW.type IS NOT OLD.type
  OR NEW.run_trigger IS NOT OLD.run_trigger OR NEW.schedule_id IS NOT OLD.schedule_id
  OR NEW.config_json IS NOT OLD.config_json OR NEW.queued_at IS NOT OLD.queued_at
BEGIN
    SELECT RAISE(ABORT, 'run request is immutable');
END;

-- A run cannot become running without an owner ...
CREATE TRIGGER runs_lease_required_on_update
BEFORE UPDATE OF status ON runs
WHEN NEW.status = 'running' AND OLD.status IS NOT 'running' AND NEW.lease_hash IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a running run needs a lease');
END;

CREATE TRIGGER runs_lease_required_on_insert
BEFORE INSERT ON runs
WHEN NEW.status = 'running' AND NEW.lease_hash IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a running run needs a lease');
END;

-- ... and once it has one, the owner never changes (a stale run is never handed to somebody else).
CREATE TRIGGER runs_lease_fixed
BEFORE UPDATE ON runs
WHEN OLD.lease_hash IS NOT NULL AND NEW.lease_hash IS NOT OLD.lease_hash
BEGIN
    SELECT RAISE(ABORT, 'the lease of a run is fixed');
END;

-- The cancel flag and its timestamp go together, and a requested cancellation cannot be withdrawn or re-dated.
CREATE TRIGGER runs_cancel_consistent_on_insert
BEFORE INSERT ON runs
WHEN (NEW.cancel_requested = 1) <> (NEW.cancel_requested_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'cancel_requested and cancel_requested_at must be set together');
END;

CREATE TRIGGER runs_cancel_consistent_on_update
BEFORE UPDATE ON runs
WHEN (NEW.cancel_requested = 1) <> (NEW.cancel_requested_at IS NOT NULL)
  OR (OLD.cancel_requested = 1 AND NEW.cancel_requested = 0)
  OR (OLD.cancel_requested_at IS NOT NULL AND NEW.cancel_requested_at IS NOT OLD.cancel_requested_at)
BEGIN
    SELECT RAISE(ABORT, 'a cancellation request cannot be changed or withdrawn');
END;
