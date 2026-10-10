# QuantumGenie Cryptographic Discovery

Local cryptographic discovery agent, backend API, SQLite datastore and browser UI.
Everything runs on one machine.

```
Web UI -> Local Backend API -> SQLite
                  ^
                  |  (agent polls for commands, posts results)
                Agent
```

## Status

Working end to end on Windows:

- **Filesystem certificate discovery**: scan folders for PEM / DER / CRT / CER / PFX / P12 files, store the certificates found,
  report them in the browser.
- **TLS discovery by active local probing**: probe the TLS services listening on this machine, store the handshake results,
  report them in the browser. This is *not* passive traffic capture; see [TLS discovery and limitations](#tls-discovery-and-limitations).
- **Scheduled (periodic) scans**: a schedule starts a filesystem or TLS scan on its own every 15 seconds to 7 days; see
  [Scheduled scans](#scheduled-scans).
- **Relationships**: when a run finishes, the certificates, hosts and probed local listeners its evidence supports are
  recorded and listed in a table on its report; see [Relationships](#relationships).
- Run lifecycle (queued, running, completed / partial / failed, cancel), a read-only report API for both scan types, and a
  browser UI with a runs list and one report page per run.

**Not implemented yet** (see [Known limitations](#known-limitations)): a relationship graph, a dashboard page and charts, and
some filesystem-report views.

## Requirements

- Windows 10 or 11. The agent uses Windows APIs (TLS listener table, process lookup, known-folder paths) and Windows
  PowerShell for PKCS#12 files. It was developed and tested on Windows 11 only.
- Python 3.11 (tested with 3.11.4).
- Node.js 20 and npm (tested with Node 20.17.0, npm 10.8.2). The UI uses Vite 6, which supports Node 20.17.
- Python packages for the backend: `requirements-backend.txt` (FastAPI, uvicorn, httpx). Packages for the tests:
  `requirements-dev.txt` (pytest, cryptography). The agent itself uses only the Python standard library.
- The version ranges in the requirements files are not pinned. This was verified with: fastapi 0.143.0, uvicorn 0.54.0,
  httpx 0.28.1, pydantic 2.14.0, starlette 1.7.0, pytest 9.1.1, cryptography 50.0.2. `frontend/package-lock.json` pins the
  UI packages.

## Quick start

Run these from the repository root in PowerShell. Calling `.venv\Scripts\python` directly means the virtual environment
does not need to be activated.

```powershell
# one-time setup
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-backend.txt -r requirements-dev.txt
cd frontend; npm ci; cd ..
```

Then start three processes, each in its own terminal:

```powershell
# 1. backend (http://127.0.0.1:8765)
.venv\Scripts\python -m backend

# 2. agent (polls the backend every 3 seconds; keep it running)
.venv\Scripts\python -m agent

# 3. browser UI (http://127.0.0.1:5173)
cd frontend; npm run dev
```

Open <http://127.0.0.1:5173>. The runs page is the start page; **Report** opens a run's report (`#/runs/<run id>`).

To try it: open **New scan**. On the **Filesystem scan** tab enter a folder that contains certificate files and press
**Run filesystem scan**; on the **TLS metadata scan** tab enter the ports to probe (or tick the explicit opt-in to probe every
eligible listener) and press **Run TLS metadata scan**. Wait for the run to reach *Completed*, then open its report. A scan
stays *Queued* until the agent picks it up; a run that no agent claims within 2 minutes fails with "No agent picked up the run
in time".

Notes:

- Backend options (`python -m backend --help`): `--db PATH` (default
  `%LOCALAPPDATA%\qg-crypto-discovery\agent.db`), `--port` (default 8765), `--data-origin {agent,sample}`. There is
  deliberately no option to bind another interface: the backend listens on `127.0.0.1` only.
- Agent options (`python -m agent --help`): `--server` (loopback URL only, default `http://127.0.0.1:8765`),
  `--poll-interval` (default 3 s), `--once` (process at most one queued run, then exit), `--agent-id`, `--batch-size`,
  `--log-level`.
- The UI's dev server forwards `/api` to `http://127.0.0.1:8765` (set in `frontend/vite.config.ts`). If you start the backend
  on another port, change that address too.
- `npm run build` type-checks and builds the UI into `frontend/dist`. Nothing in this repository serves that folder; the UI
  is run through the Vite dev server as shown above. (`vite preview` is configured in `vite.config.ts` but has not been tried.)
- The backend has no authentication: it is local-only by design. It refuses requests whose `Host` is not a loopback name and
  browser requests whose `Origin` is not a loopback origin.

## Privileges

- **No Administrator rights are needed** for either scan type.
- Filesystem scans run as the user who started the agent. Folders and files that user cannot read are recorded as errors
  and the run ends as *Partial* or *Failed*; they are not skipped silently.
- TLS probing reads the operating system's listener table and connects to this machine's own listeners. Process name and
  executable path come from the OS and may be unavailable for some system processes; the record then says so.
- PKCS#12 (`.pfx` / `.p12`) files are opened through a fixed Windows PowerShell script (no password is ever used or guessed).

## Components

| Part | Where | What it does |
|---|---|---|
| Agent | `agent/` (Python standard library only) | Polls the backend for queued runs, claims one, scans, uploads records in batches, finishes the run. `python -m agent`. |
| Backend | `backend/` (FastAPI + SQLite) | Creates and tracks runs, runs the scheduler, validates and stores what the agent sends, serves the report API. `python -m backend`. |
| Browser UI | `frontend/` (React + TypeScript + Vite) | Runs list, "New scan" panel (filesystem and TLS metadata scans), "Scheduled scans" panel, filesystem report, TLS report. |
| Tests | `tests/`, `frontend/src/**/*.test.*` | See [Testing](#testing). |

How a run works: the UI (or any HTTP client) calls `POST /api/runs`; the run is *queued*. The agent finds it with
`GET /api/runs?status=queued`, claims it (`POST /api/runs/{id}/claim`, which returns a private lease token), sends heartbeats,
uploads numbered record batches (idempotent by sequence number) and finishes. The backend alone decides the final status
(*completed*, *partial* or *failed*) from the evidence it stored. A run can be cancelled while queued or running.

HTTP API summary (all JSON, under `/api`):

- Runs: `POST /runs` (creates a *manual* run; scheduled runs are created only by the scheduler), `GET /runs` (filters `type`,
  `status`, `limit`, `offset`), `GET /runs/{id}`, `POST /runs/{id}/cancel`. Agent-only calls: `claim`, `heartbeat`,
  `observations`, `finish`.
- Schedules: `POST /schedules`, `GET /schedules`, `GET /schedules/{id}`, `PATCH /schedules/{id}` (pause or resume).
- Filesystem report: `GET /runs/{id}/fs/summary`, `/fs/observations`, `/fs/certificates`, `/runs/{id}/issues`,
  `GET /certificates/{sha256}`.
- TLS report: `GET /runs/{id}/tls/summary`, `/tls/observations`, `/tls/issues`.
- Other: `GET /meta`, `GET /dashboard`, `GET /runs/stats`.
- A report endpoint of the wrong type for a run answers `409 wrong_run_type`.

## Scheduled scans

A schedule runs a filesystem or TLS scan again and again without anyone pressing a button. Create one in the **Scheduled scans**
panel on the runs page, or through the API. Its runs are ordinary runs that the agent picks up like any other; in the runs list
they show the trigger **Scheduled** and the schedule's id.

Rules (all enforced by the backend, which runs the scheduler inside the same process and checks every 5 seconds):

- **Interval:** a whole number of seconds from 15 to 604,800 (7 days), inclusive. The first run is due one full interval after the
  schedule is created, or resumed after a pause. Times are stored in UTC; an interval is a plain duration, so time zones and
  daylight saving do not move a schedule.
- **One scan at a time.** The agent runs one scan at a time. If any run is queued or running when a schedule falls due, that
  occurrence is **skipped** and the next one is a full interval later; occurrences are never queued up. A stale queued or
  running run is expired by the normal run lifecycle first.
- **Downtime:** if the backend was stopped (or the computer asleep) past a due time, the schedule runs **once** when the backend
  is back, not once per missed interval.
- **Scheduled scans need the agent started.** The scheduler does not check for an agent; a scheduled run that nobody picks up
  fails after 2 minutes like any other.
- **TLS safety:** a TLS schedule needs explicit ports, or the explicit opt-in `probe_all_listeners: true` (the form's checkbox).
  Without either, the backend refuses to create it. The opt-in is stored with the schedule and checked again every time it fires.
  A schedule cannot name a host or address; ports can only narrow the listeners found on this machine.
- **Configuration** goes through the same checks as a manual run's (known keys, ranges, no key material).
- **Pause and resume only.** A schedule cannot be edited or deleted in this version; to change one, pause it and create another.
  At most 50 schedules exist.
- **States** shown for a schedule: *Paused*; *Waiting* (enabled and no run is queued or running); *Skipping* (enabled while a run
  is queued or running, so an occurrence falling due now would be skipped). The last run's status is the run's own lifecycle
  status; nothing is reported as completed before the run is.

Create a schedule from PowerShell (a TLS schedule against one port, every 30 seconds):

```powershell
$body = @{ run_type = "tls"; interval_seconds = 30; config = @{ ports = @(8443) } } | ConvertTo-Json -Depth 5
(Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api/schedules -ContentType "application/json" -Body $body).schedule
Invoke-RestMethod http://127.0.0.1:8765/api/schedules                       # list them
Invoke-RestMethod -Method Patch -Uri http://127.0.0.1:8765/api/schedules/<schedule id> -ContentType "application/json" -Body '{"enabled": false}'   # pause
```

## Relationships

When a run finishes, the backend records the relationships its own stored evidence supports, in the same transaction that
finalizes the run. Every report lists them in a **Relationships** table (`GET /api/runs/{run_id}/relationships`: read-only,
at most 500 rows, deterministic order).

| Relationship | Recorded when | What it means |
|---|---|---|
| certificate to host (`stored_on`) | a filesystem scan parsed the certificate from a file | The file exists on the host that ran the scan. It does not show the certificate is in use. |
| local listener to certificate (`presented_certificate`) | a *completed* TLS handshake against a listener on this machine returned the certificate (one row per certificate in the chain) | The certificate was returned by an active probe. There is no remote peer, direction or packet count. |

- The agent probes listeners on this machine and observes no traffic, so the schema's `communicates_with` edge kind is never
  used. A probed listener is an endpoint scoped to the host that has it, so two machines' `127.0.0.1:443` never merge.
- A listening process is shown on a TLS row only when every completed probe of that listener in the run was attributed to the
  same process. It is read when the report is requested, never stored, and a PID never identifies anything. Filesystem scans
  carry no process data.
- A TLS row also lists *separate* evidence when filesystem scans stored a file with the same SHA-256 (host, number of runs,
  latest run). That does not show the listener uses that file.
- Repeating a scan strengthens an edge: each row shows its observations in this run and its observations and runs across all
  runs. Recording is idempotent, and each run keeps its own contribution.
- Each report says how recording compares with the evidence: *recorded*, *No relationships expected*, *Not recorded for this
  run* (a run made before relationships existed, or one whose recording failed; nothing is backfilled or inferred) or *Only
  partly recorded*. While a run is queued or running, nothing is recorded yet.

## Filesystem discovery

- Looks for files with these extensions: `.pem .crt .cer .cert .der .pfx .p12`. Certificates are read from PEM bundles, DER
  files and PKCS#12 containers.
- Roots: the folders you give, or, if you give none, the agent's default locations that exist on the machine (Downloads,
  Documents, Desktop, `~\.aspnet\https`, `%ProgramData%`, `%ProgramFiles%\Git`).
- Each certificate is stored once, keyed by its SHA-256 fingerprint; every place it was seen is a separate sighting. Stored
  facts: path, format, fingerprint, serial, subject, issuer, SAN, chain position, key algorithm and size, signature
  algorithm, validity dates, days to expiry, validity status, parse status, access errors and a confidence level.
- **Private keys are never copied or stored.** Key material found next to certificates (for example in a PEM bundle or a
  PKCS#12 file) is not read into any record. Certificate files are opened read-only and never modified. This is covered by
  the tests in `tests/agent/test_key_safety.py`, `test_fs_scan_safety.py` and `test_fs_scan_pfx.py`.
- Known limit: for PKCS#12 files the OS decrypts the certificate containers; those certificates carry the warning
  `pkcs12_integrity_not_verified` and at most medium confidence (details in `agent/pfx_bridge.py`).
- Configuration keys accepted when creating a filesystem run: `roots`, `extensions`, `exclude_dir_names`, `exclude_paths`,
  `max_file_bytes`, `max_entries`, `max_candidates`, `max_certs_per_file`, `max_depth`, `expiring_days`,
  `time_budget_seconds`. Any other key is refused with `422 invalid_config`. Defaults: 16 MiB per file, depth 12, 10-minute
  time budget, "expiring" means within 30 days.

Create a filesystem run from PowerShell (the UI form does the same):

```powershell
$body = @{ type = "filesystem"; config = @{ roots = @("C:\certs") } } | ConvertTo-Json -Depth 5
(Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8765/api/runs -ContentType "application/json" -Body $body).run
```

## TLS discovery and limitations

**Method: active local TLS service probing.** The agent reads the operating system's table of listening TCP sockets on this
machine and makes one TLS handshake attempt against each eligible listener. It does **not** capture packets, decrypt
traffic, or observe other applications' connections, and it never sends application data.

What a TLS observation is: **one probe attempt**, not an observed connection.
- Every record says so: `direction` is `unknown`, `local_*` / `remote_*` are empty, `event_count` is 1 (one probe attempt),
  `packet_count` is 0 (packet counts are unavailable: nothing is captured), and the warnings always include `active_probe` and
  `packet_counts_unavailable`. The source address and port are the probe's own socket; the destination is the listener.
- Only a **completed** handshake is counted as a TLS finding. A failed, incomplete or alert result is stored as evidence
  (with no version, cipher or certificate) and is never counted; a non-TLS listener is never presented as a TLS service.
- The peer certificate is recorded as parsed facts (fingerprint, subject, issuer, SAN, key, validity). Raw certificate bytes are
  never sent to the backend or stored. The full chain needs a private CPython API; when it is unavailable only the leaf is
  recorded and the record says so (`chain_unavailable`).

Limits and safety:
- Targets come only from the OS listener table, never from user input. A run's `ports` list can only narrow that table.
  Wildcard listeners are probed through loopback (`127.0.0.1`, `::1`). Host names, remote addresses, multicast, unspecified and
  link-local addresses are never contacted. Before connecting, the probe binds its socket to the destination address, which the
  OS only allows for an address that belongs to this machine.
- Trust and host names are **not** evaluated (the certificate is not verified, and no SNI is sent). Servers that only accept
  legacy protocol versions or require a client certificate or SNI may show as failed or incomplete.
- A handshake attempt sends a TLS ClientHello to every listener probed, including non-TLS services, which may log it. Probing
  runs only when a TLS scan is requested. A scan is bounded by a target cap, connect and handshake timeouts, and a time budget.
- Process attribution (PID, executable) comes from the OS listener table and may be unavailable (for example for system
  processes); the record then says `not_found` or `unavailable` instead of guessing.
- A TLS run's configuration accepts only `max_targets`, `connect_timeout_seconds`, `handshake_timeout_seconds`,
  `time_budget_seconds` and `ports`; any other key is refused when the run is created.
- Wording: the backend uses one counted reason token, `file_errors:N`, for both run types. In a TLS run it counts scan errors
  (a failed listener enumeration, or a probe that could not be made), not files. The stored token is unchanged; the UI words
  it as "scan errors" for TLS runs and "read errors" for filesystem runs.
- Needs no Administrator rights. Windows only.

### Creating a TLS run through the API

The browser UI starts TLS scans from its **TLS metadata scan** tab. It asks for ports, and it only probes every eligible
listener when you tick an explicit opt-in. The same scan can be started through the API, as shown below. The agent must be
running. **Always pass `ports`** so that the run probes only listeners you chose; without it the agent probes every eligible
listener on the machine (up to 128).

1. List the listeners you could probe:

   ```powershell
   Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
     Select-Object LocalAddress, LocalPort, OwningProcess,
       @{n='Process'; e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize
   ```

2. Create the run, wait for it to finish and read the results (replace `8443` with one of your ports):

   ```powershell
   $base = "http://127.0.0.1:8765"
   $body = @{ type = "tls"; config = @{ ports = @(8443) } } | ConvertTo-Json -Depth 5
   $id   = (Invoke-RestMethod -Method Post -Uri "$base/api/runs" -ContentType "application/json" -Body $body).run.run_id

   do {                                                   # queued -> running -> completed | partial | failed
     Start-Sleep -Seconds 2
     $run = (Invoke-RestMethod "$base/api/runs/$id").run
     "{0}  records={1} handshakes={2}" -f $run.status, $run.record_count, $run.finding_count
   } while ($run.status -in "queued", "running")

   Invoke-RestMethod "$base/api/runs/$id/tls/summary"      | ConvertTo-Json -Depth 8
   Invoke-RestMethod "$base/api/runs/$id/tls/observations" | ConvertTo-Json -Depth 8
   Invoke-RestMethod "$base/api/runs/$id/tls/issues"       | ConvertTo-Json -Depth 8
   ```

   Open `http://127.0.0.1:5173/#/runs/<run id>` to see the same run as a report.

Accepted `config` keys and limits: `ports` (1 to 256 whole numbers, 1 to 65535), `max_targets` (1 to 1024, default 128),
`connect_timeout_seconds` (default 2) and `handshake_timeout_seconds` (default 3), both above 0 and at most 30, and
`time_budget_seconds` (default 60, at most 3600). `config` may be empty. The only other `type` value is `"filesystem"`.

Optional, to have a TLS service to look at: this starts a throwaway TLS listener and a plain-text listener on loopback using
the test fixtures (needs the packages from `requirements-dev.txt`). It prints both ports, generates a self-signed
test certificate and key in a temporary folder (`demo_tls_*` under your temp directory, printed), and runs for an hour or until
you press Ctrl+C. Delete that folder afterwards.

```powershell
.venv\Scripts\python -c "import sys,tempfile,pathlib,time; sys.path[:0]=['.','tests/agent']; from tlsfx import TlsServer,PlainServer,make_material; d=pathlib.Path(tempfile.mkdtemp(prefix='demo_tls_')); m=make_material(d,chain=True); t=TlsServer(m); p=PlainServer(); print('TLS port',t.port,'plain-text port',p.port,'key folder',d,flush=True); time.sleep(3600)"
```

Run a TLS scan with `ports = @(<TLS port>, <plain-text port>)`: expect one completed handshake (a finding, with a
three-certificate chain) and one plain-text listener that is *not* a TLS finding.

## Sample data vs. real evidence

No sample data is shipped. The database records its origin (`agent` or `sample`) once, when it is created
(`--data-origin`), and the backend refuses to open a database with a different origin than requested, so sample data and
agent evidence cannot be mixed in one file. `GET /api/meta` reports the origin. The UI does not display it yet.

## Known limitations

Not implemented:
- **Relationship graph.** Relationships are shown as a table per run; there is no graph. A filesystem report lists only
  `stored_on` rows and a TLS report only `presented_certificate` rows (plus the separate filesystem evidence described
  above). Runs made before relationships were recorded are not backfilled and read "Not recorded for this run".
- **Dashboard page and charts.** `GET /api/dashboard` and `GET /api/runs/stats` exist; the UI uses neither. Summary figures are
  shown as numbers; there are no charts.
- **Filesystem report views.** The report lists certificates and files and shows validity counts, but there are no views by
  key algorithm, key size, issuer or location, although the summary endpoint returns those figures.
- **Filesystem owning process.** Always empty.
- **Serving the built UI.** Only the Vite dev server is used.

By design or by nature of the method:
- TLS data is from active probing: direction is always `unknown`, packet counts are unavailable, no SNI or host name is sent,
  and trust is not evaluated. See the TLS section above.
- Windows only (agent). The backend has no authentication and must stay on loopback.
- The agent prints "no queued filesystem run" when `--once` finds nothing, although it also handles TLS runs.

## Agent package size

The agent is 16 Python source files in `agent/` and imports only the standard library. Measured (source only, no bundled
interpreter, no packaging step): 146,851 bytes of source, **50,647 bytes** zipped, against the 5 MB limit. To measure it again:

```powershell
.venv\Scripts\python -c "import io,zipfile,pathlib; b=io.BytesIO(); z=zipfile.ZipFile(b,'w',zipfile.ZIP_DEFLATED); [z.write(p) for p in sorted(pathlib.Path('agent').glob('*.py'))]; z.close(); print(len(b.getvalue()))"
```

The web app (`frontend/`) and its dependencies are separate from the agent and are not part of that figure.

## Testing

```powershell
.venv\Scripts\python -m pytest -q          # agent and backend tests: 3,628 tests
cd frontend
npm run typecheck                          # tsc --noEmit
npm test                                   # vitest run
npm run build                              # type-check, then production build into frontend/dist
cd ..
git diff --check                           # whitespace check of uncommitted changes
```

Some tests start real loopback servers (a backend, local TLS and plain-text listeners) and run the backend and agent as
separate processes; they use temporary folders and databases and nothing outside the test run.

What has and has not been verified:
- Verified by automated tests: the agent, ingestion, run lifecycle, report API and UI behavior above, including that
  private-key material and raw certificate bytes do not reach the database or API responses.
- Verified by scripted (automated) headless-browser checks against a live backend, agent and Vite server during development:
  the runs list, filesystem report and TLS report.
- Not verified: a clean-machine install following this README, other Windows versions, and manual testing by a person in
  a browser for every screen.
- At an earlier stage of development one full-suite run had a single failing test (1 failed, 2912 passed) whose cause was
  never identified. Later full runs passed, but that failure is not considered explained or resolved.
