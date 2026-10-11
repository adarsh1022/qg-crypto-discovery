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
- **Dashboard**: key figures and charts (runs by status and type, certificate validity, key and signature algorithms, TLS
  versions and cipher suites); see [Dashboard](#dashboard).
- Run lifecycle (queued, running, completed / partial / failed, cancel), a read-only report API for both scan types, and a
  browser UI with a runs list and one report page per run.

**Not implemented yet** (see [Known limitations](#known-limitations)): a relationship graph, charts of duration or findings
over time, issuer and location charts, and some filesystem-report views.

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
| Browser UI | `frontend/` (React + TypeScript + Vite) | Runs list, "New scan" panel (filesystem and TLS metadata scans), "Scheduled scans" panel, filesystem report, TLS report (both with a relationships table), dashboard. |
| Tools | `tools/` (Python standard library; the demo certificates need `cryptography`) | `build_agent_pyz.py` builds the agent package; `make_demo_certs.py` writes synthetic certificate files to scan in a demo. |
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
- Relationships (both run types): `GET /runs/{id}/relationships`.
- Other: `GET /meta`, `GET /dashboard`, `GET /runs/stats`.
- A report endpoint of the wrong type for a run answers `409 wrong_run_type`.

## Third-party dependencies

The agent has **no third-party dependency**: it uses only the Python standard library (a test checks this). SQLite comes from the
standard library as well. Versions below are the ones installed when this section was written; the Python ranges are in
`requirements-backend.txt` and `requirements-dev.txt` (not pinned), and the UI packages are pinned exactly in
`frontend/package.json` and `frontend/package-lock.json` (lockfile version 3, 199 packages including transitive ones).

**Backend, `requirements-backend.txt`**

| Package | Tested with | Why it is used |
|---|---|---|
| fastapi | 0.143.0 | HTTP API framework and request validation |
| pydantic | 2.14.0 | installed by FastAPI; the response models that decide which fields may leave the service |
| starlette | 1.7.0 | installed by FastAPI; the ASGI toolkit underneath it |
| uvicorn | 0.54.0 | the server behind `python -m backend`, bound to `127.0.0.1` only |
| httpx | 0.28.1 | listed with the backend packages but used only by tests (FastAPI's test client and loopback HTTP calls); the backend never calls out |

**Python tests and tools, `requirements-dev.txt`**

| Package | Tested with | Why it is used |
|---|---|---|
| pytest | 9.1.1 | test runner |
| cryptography | 50.0.2 | generates test certificates, serves as an independent oracle for the hand-written X.509 parser, and builds the demo certificates in `tools/make_demo_certs.py`. Not used by the agent or the backend. |

**Web UI, `frontend/package.json`**

| Package | Version | Why it is used |
|---|---|---|
| react, react-dom | 18.3.1 | the user interface (runtime) |
| vite, @vitejs/plugin-react | 6.4.4, 4.7.0 | development server and production build |
| typescript | 5.9.3 | type checking |
| vitest, jsdom | 4.1.11, 26.1.0 | test runner and simulated browser |
| @testing-library/react, /dom, /user-event | 16.3.1, 10.4.2, 14.6.5 | component tests |
| @types/node, @types/react, @types/react-dom | 20.19.43, 18.3.31, 18.3.7 | type definitions |

There is no router, state-management, chart or CSS library: routing is a small hash router, the charts are plain HTML bars, and
the styles are one CSS file. Scripted checks in a headless Chrome were used during development; Chrome is not a dependency.
Windows PowerShell (part of Windows) is used by the agent to open PKCS#12 files. Tested with Python 3.11.4, Node 20.17.0 and npm 10.8.2.

## AI tools used

This project was built with an AI coding assistant, and that should be read as the main way it was developed, not an aside.

- **Tool and models:** Claude Code (Anthropic's coding agent, used from the command line and the VS Code extension) with Claude
  models. Every commit in this repository's history carries a `Co-Authored-By: Claude Sonnet 5.5` trailer (23 of 23 commits when
  this section was written). The trailer records the model named at commit time; it cannot show which model wrote which line.
- **What the assistant did:** planning and phasing, designing the data model and API rules, writing and refactoring the agent, the
  backend and the web UI, writing the tests (including independent test oracles, mutation checks and scripted headless-browser
  checks), generating the synthetic test data, and writing this documentation. A bundled Anthropic data-visualization guide, with its
  palette-validation script, was used to choose and check the chart colours.
- **What the author did:** supplied the assignment, set the scope, approved each phase and design decision, reviewed the
  assistant's reports and test results, and decides what is submitted. Responsibility for the submitted work is the author's.
- **At run time:** the application contains no AI or language-model calls. It sends nothing off the machine: the agent talks only to
  the backend on loopback, and the browser only to the local development server and backend.
- **What is not claimed:** AI-written code has not been independently audited. The automated tests, and the
  limits listed under [Known limitations](#known-limitations) and [Testing](#testing), are the evidence of quality, not the use of AI.

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

## Dashboard

The **Dashboard** link in the header (`#/dashboard`) shows key figures and charts. It reads existing read-only endpoints when
the page opens and when you press **Refresh**; it does not poll.

| Chart | Where the numbers come from |
|---|---|
| Runs by status and type | `GET /api/runs/stats` (`by_type_status`: every run, whatever its age) |
| Certificate validity, key algorithms, signature algorithms | `GET /api/dashboard` (`summary` of the **latest finished filesystem run**) |
| TLS versions, cipher suites | `GET /api/runs?type=tls&limit=100` to find the latest finished TLS run (completed or partial), then `GET /api/runs/{id}/tls/summary` (completed handshakes only) |

- The certificate and TLS charts each describe **one run** and say which, with a link to its report. They do not describe all
  runs. If that run found nothing, or did not complete cleanly, the chart says so; for example, a scheduled scan of an empty
  folder that happens to be the latest finished filesystem run leaves the certificate charts empty until a scan that finds
  certificates finishes after it.
- The charts are plain HTML bars (no chart library). Every bar is a list item with its label and number in text, status colours
  (valid, expiring, expired) always come with an icon and a text label, and the bars are scaled to the largest row of their own
  chart.
- Not charted: duration or findings over time, issuers, file locations, TLS certificate validity, and any relationship graph.

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

## Demo script (about 5 minutes)

Prepare before recording (this is not part of the five minutes). It uses a fresh database and synthetic certificates, so nothing
real is shown:

```powershell
.venv\Scripts\python tools\make_demo_certs.py          # 7 certificate-only files in demo_certs\ (no private keys)
.venv\Scripts\python -m backend --db .\demo.db         # terminal 1: a database just for the demo
.venv\Scripts\python -m agent                          # terminal 2
cd frontend; npm run dev                                # terminal 3
```

Start the throwaway TLS listener from [Creating a TLS run through the API](#creating-a-tls-run-through-the-api) in a fourth
terminal and note its **TLS port**. Open <http://127.0.0.1:5173>.

| Time | Show | Say |
|---|---|---|
| 0:00 | The three terminals, then the empty Discovery runs page | Local only: agent, backend on `127.0.0.1`, browser UI. Nothing leaves the machine. |
| 0:25 | **New scan**, filesystem tab, folder `demo_certs`, **Run filesystem scan**; watch Queued, Running, Completed | A real scan of real files by the agent as the current user; no administrator rights. |
| 1:00 | Open the report: summary, certificates (one stored twice), Files tab | Private keys are never copied or stored; a certificate seen in two files is one certificate with two sightings. |
| 1:30 | The **Relationships** table on that report | A certificate was parsed from a file on this host. That shows the file exists, not that the certificate is in use. |
| 2:00 | **TLS metadata scan** tab (read the scope text), enter the TLS port, **Run TLS metadata scan**, open its report | An active probe of this machine's own listeners, not traffic capture; direction and packet counts are unknown. |
| 2:40 | TLS report: the completed handshake, then its **Relationships** row | A local listener presented this certificate. The process is shown only when unambiguous. The "same certificate in files" column is separate evidence and does not prove the listener uses that file. |
| 3:10 | **Dashboard** | Runs by status and type, validity (valid, expiring, expired), key and signature algorithms, TLS versions and cipher suites. Each chart says which run it describes. |
| 3:50 | **Scheduled scans**: new schedule, every 15 seconds, folder `demo_certs`; watch Scheduled runs appear; pause it | Periodic scans; one scan at a time, and a due scan is skipped while another is running. |
| 4:25 | Optional: `python tools\build_agent_pyz.py` then `python dist\qg-agent.pyz --help` | The agent packages into about 50 KB, far below the 5 MB limit. |
| 4:40 | The README's Known limitations and AI tools sections | No relationship graph yet; TLS is active probing only; the backend has no authentication and stays on loopback; Windows only; AI-assisted development is disclosed. |

Notes: schedule a folder that holds certificates (not an empty one), because the dashboard describes the latest *finished*
filesystem run and an empty scan would leave its certificate charts empty. If a step fails during a take, stop and restart the
take rather than explaining around it.

## Known limitations

Not implemented:
- **Relationship graph.** Relationships are shown as a table per run; there is no graph. A filesystem report lists only
  `stored_on` rows and a TLS report only `presented_certificate` rows (plus the separate filesystem evidence described
  above). Runs made before relationships were recorded are not backfilled and read "Not recorded for this run".
- **More charts.** The [Dashboard](#dashboard) charts runs, validity, key and signature algorithms, TLS versions and cipher
  suites. There are no charts of duration or findings over time, issuers or file locations, and the per-run reports show
  those figures as numbers only.
- **Filesystem report views.** The report lists certificates and files and shows validity counts, but it has no views by
  key algorithm, key size, issuer or location, although the summary endpoint returns those figures (the dashboard charts the
  algorithms for the latest finished filesystem run).
- **Filesystem owning process.** Always empty.
- **Serving the built UI.** Only the Vite dev server is used.

By design or by nature of the method:
- TLS data is from active probing: direction is always `unknown`, packet counts are unavailable, no SNI or host name is sent,
  and trust is not evaluated. See the TLS section above.
- Windows only (agent). The backend has no authentication and must stay on loopback.
- The agent prints "no queued filesystem run" when `--once` finds nothing, although it also handles TLS runs.

## Agent package

The agent is the 16 Python source files in `agent/` and imports only the standard library, so its package is just that source.
Build it as one runnable file from the repository root:

```powershell
.venv\Scripts\python tools\build_agent_pyz.py        # needs only Python 3.9 or newer; nothing is installed
```

It writes `dist\qg-agent.pyz` (ignored by git) and prints the size and SHA-256. Measured with the agent source at this commit:
**50,590 bytes** (49.4 KiB), about 1 % of the 5 MB (5,242,880 bytes) limit. The script exits with an error and writes nothing if
the archive would be larger than the limit.

Run it exactly like `python -m agent` (same options, same behavior):

```powershell
python dist\qg-agent.pyz --help
python dist\qg-agent.pyz                       # keep running; polls the backend at http://127.0.0.1:8765
python dist\qg-agent.pyz --once                # process at most one queued run, then exit
```

- **Contents:** `agent/*.py` and a two-line `__main__.py`. Nothing else: no virtual environment, caches, tests, fixtures, backend
  or frontend. No dependency and no interpreter is bundled, so running it needs Python 3.11 on the machine (and Windows for the
  OS-specific parts), as before.
- **Reproducible:** entries are sorted and carry a fixed timestamp and permissions, and line endings are normalised, so the same
  source gives the same bytes on any checkout.
- **Tested** (`tests/tools/`): the archive's exact contents, the size limit, reproducibility, that `--help` and a bad argument
  behave like `python -m agent`, and a real run: a backend process, a queued scan and the packaged agent finishing it with the same
  results as `python -m agent`.
- The web app (`frontend/`) and the backend are separate from the agent and are not part of that figure.

## Testing

```powershell
.venv\Scripts\python -m pytest -q          # agent, backend and tools tests: 3,891 tests (about 5 minutes)
cd frontend
npm run typecheck                          # tsc --noEmit
npm test                                   # vitest run: 588 tests
npm run build                              # type-check, then production build into frontend/dist
cd ..
git diff --check                           # whitespace check of uncommitted changes
```

Some tests start real loopback servers (a backend, local TLS and plain-text listeners) and run the backend and agent as
separate processes; they use temporary folders and databases and nothing outside the test run. The test counts above are from the
last full run before this README was committed; a few tests (PKCS#12 handling) call the real Windows PowerShell, see below.

What has and has not been verified:
- Verified by automated tests: the agent, ingestion, run lifecycle, report API and UI behavior above, including that
  private-key material and raw certificate bytes do not reach the database or API responses.
- Verified by scripted (automated) headless-Chrome checks against a live backend, agent and Vite server during development:
  the runs list, both scan forms, filesystem and TLS reports, the relationships table and its states, scheduling, error and retry
  paths, and the dashboard (every drawn number compared with the API's). These were run by a script, not by a person.
- Verified once in a fresh environment (a copy of the committed files, a new virtual environment and `npm ci` from the lockfile,
  on the same Windows 11 machine, with Python 3.11.4, Node 20.17.0 and npm 10.8.2): the setup commands in Quick start, building
  the agent package, and starting the backend, agent and UI with the documented commands. See the next bullets for what that does
  not cover.
- Not verified: a clean *machine* (the fresh environment shared this computer's Python, Node and PowerShell), other Windows
  versions, other browsers, and manual testing by a person in a browser for every screen.
- At an earlier stage of development one full-suite run had a single failing test (1 failed, 2912 passed) whose cause was
  never identified. Later full runs passed, but that failure is not considered explained or resolved. Since then single tests
  that call the real Windows PowerShell for PKCS#12 files (in `tests/agent/test_pfx_bridge_windows.py` and
  `test_fs_scan_pfx.py`) failed once each in separate full runs and passed on every rerun, including six isolated reruns of
  the affected tests; the cause was not found, and this may be the same intermittent problem.
