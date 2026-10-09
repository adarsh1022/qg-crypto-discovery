"""A deterministic, varied dataset for report tests, and an independent oracle that re-implements the search, filter,
sort and duplicate rules in plain Python straight from their definitions (not from the SQL)."""
from backend import fs_ingest
from ingestfx import at, failure_record, ok_record, pfx_record, running_run

ALGORITHMS = [("RSA", 2048, None), ("RSA", 3072, None), ("RSA", 4096, None), ("EC", 256, "secp256r1"),
              ("EC", 384, "secp384r1"), ("Ed25519", 256, None)]
SIGNATURES = ["sha256WithRSAEncryption", "ecdsa-with-SHA256", "sha1WithRSAEncryption", "ecdsa-with-SHA384", "ed25519"]
ISSUERS = ["CN=Alpha CA", "CN=beta CA", "CN=Zeta CA", "CN=Ünï Root"]
NOT_AFTER = ["2025-12-01T00:00:00Z", "2026-03-10T00:00:00Z", "2026-06-01T00:00:00Z", "2027-01-01T00:00:00Z", "2030-01-01T00:00:00Z"]
ROOT_C, ROOT_D = "C:\\certs", "D:\\data"


def facts(n: int) -> dict:
    """Certificate facts that are the SAME every time certificate number n is seen (identity is the fingerprint)."""
    algorithm, size, curve = ALGORITHMS[n % len(ALGORITHMS)]
    subject = "CN=Zoë 😀 Service" if n == 7 else (f"CN=host{n}.Example.COM" if n % 2 else f"CN=svc{n}.internal.test")
    san = [{"type": "DNS", "value": "API.Internal.Test" if n == 5 else f"host{n}.example.com"}]
    if n % 3 == 0:
        san.append({"type": "IP Address", "value": f"10.0.0.{n}"})
    return dict(key_algorithm=algorithm, key_size=size, key_curve=curve, signature_algorithm=SIGNATURES[n % len(SIGNATURES)],
                issuer=ISSUERS[n % len(ISSUERS)], subject=subject, san=san, not_after=NOT_AFTER[n % len(NOT_AFTER)],
                is_ca=[True, False, None][n % 3])


def cert(path, n, root=None, **overrides):
    return ok_record(path, n, scan_root=root or path.rsplit("\\", 1)[0], **{**facts(n), **overrides})


def pfx(path, n, root, **overrides):
    return pfx_record(path, n, scan_root=root, **{**facts(n), **overrides})


def failure(path, status, root, **overrides):
    return failure_record(path, status, scan_root=root, **overrides)


def build_records() -> list[dict]:
    records = [cert(f"{ROOT_C}\\site{n}.pem", n, ROOT_C) for n in range(1, 13)]
    records += [cert(f"{ROOT_D}\\backup\\site1.crt", 1, ROOT_D, format="der"),                       # the same certificate again
                cert(f"{ROOT_D}\\backup\\site2.crt", 2, ROOT_D, format="der", warnings=["serial_not_positive"],
                     evidence_confidence="medium")]
    records += [pfx(f"{ROOT_C}\\store\\bundle.pfx", n, ROOT_C) for n in (2, 3, 3, 4)]               # 3 twice inside one file
    records += [pfx(f"{ROOT_D}\\other.pfx", n, ROOT_D) for n in (3, 5, 5)]                           # 3 again elsewhere; 5 twice
    for name, n in (("100%_done.pem", 6), ("a_b.pem", 7), ("aXb.pem", 8), ("O'Brien.pem", 9), ('q"uote.pem', 10),
                    ("semi;colon.pem", 11), ("dash--dash.pem", 12), ("br[ack]et.pem", 1), ("ÉCOLE.pem", 5)):
        records.append(cert(f"{ROOT_D}\\odd\\{name}", n, ROOT_D, extension_mismatch=(n % 2 == 0)))
    records.append(cert(f"{ROOT_D}\\证书\\é.pem", 7, ROOT_D))
    records += [failure(f"{ROOT_C}\\locked1.pem", "access_denied", ROOT_C),
                failure(f"{ROOT_C}\\gone.pem", "read_error", ROOT_C, detail="internal_error", access_error=None),
                failure(f"{ROOT_C}\\bad.pem", "malformed", ROOT_C, detail="x509_malformed: truncated", access_error=None),
                failure(f"{ROOT_D}\\huge.pem", "too_large", ROOT_D, detail="file_too_large", access_error=None),
                failure(f"{ROOT_D}\\key.pem", "no_certificate", ROOT_D, detail="no_certificate_block", access_error=None),
                failure(f"{ROOT_D}\\cloud.pem", "skipped", ROOT_D, detail="cloud_placeholder", access_error=None)]
    return records


def load(conn, records, run_id=None, *, start=0, batch=7):
    """Ingest through the real ingestion code, in small batches (so seq / insertion order can be controlled)."""
    run_id = run_id or running_run(conn)
    items = [(start + i, r) for i, r in enumerate(records)]
    for offset in range(0, len(items), batch):
        result = fs_ingest.ingest_fs_batch(conn, run_id, items[offset:offset + batch], now=at(2))
        assert result.rejected == () and result.conflicts == (), result
    return run_id


# ------------------------------------------------------------------ the oracle
def ascii_lower(text):
    return "".join(c.lower() if c.isascii() else c for c in text) if isinstance(text, str) else text


def expected(records, seqs=None):
    """Oracle rows: one per record, with duplicate_kind from the definitions (seq order; same path vs other path)."""
    seqs = seqs if seqs is not None else range(len(records))
    rows, seen_fp, seen_fp_path, path_count = [], set(), set(), {}
    for seq, r in sorted(zip(seqs, records), key=lambda pair: pair[0]):
        fp, path = r["sha256"], r["path"]
        if fp is None or fp not in seen_fp:
            kind = "none"
        elif (fp, path) in seen_fp_path:
            kind = "within_file"
        else:
            kind = "across_files"
        if fp is not None:
            seen_fp.add(fp)
            seen_fp_path.add((fp, path))
        ordinal = path_count.get(path, 0)
        path_count[path] = ordinal + 1
        rows.append(dict(r, seq=seq, duplicate_kind=kind, entry_ordinal=ordinal,
                         san_values=[s["value"] for s in (r["san"] or [])], has_warnings=bool(r["warnings"])))
    return rows


def folded(text):
    return text.casefold()


def match_q(row, q):
    needle = folded(q)
    texts = [row["path"], row["filename"], row["subject"], row["issuer"], row["serial_hex"], *row["san_values"]]
    return any(t is not None and needle in folded(t) for t in texts)


def keep_sighting(row, **f):
    for name in ("parse_status", "validity_status", "format", "chain_role", "evidence_confidence", "scan_root",
                 "duplicate_kind", "key_algorithm", "key_size", "signature_algorithm", "issuer", "has_warnings"):
        if f.get(name) is not None and row[name] != f[name]:
            return False
    if f.get("fingerprint") is not None and not (row["sha256"] or "").startswith(f["fingerprint"].lower()):
        return False
    return f.get("q") is None or match_q(row, f["q"])


NOCASE = {"path", "filename", "scan_root", "subject", "issuer"}


def ordered(rows, sort, direction, tie):
    present = [r for r in rows if r[sort] is not None]
    missing = [r for r in rows if r[sort] is None]
    key = (lambda r: ascii_lower(r[sort])) if sort in NOCASE else (lambda r: r[sort])
    present = sorted(sorted(present, key=lambda r: r[tie]), key=key, reverse=(direction == "desc"))
    return present + sorted(missing, key=lambda r: r[tie])


def sightings(records, seqs=None, *, sort="seq", direction="asc", **filters):
    rows = [r for r in expected(records, seqs) if keep_sighting(r, **filters)]
    return ordered(rows, sort, direction, "seq")


def unique(records, seqs=None, *, sort="sha256", direction="asc", min_sightings=None, is_ca=None, **filters):
    rows = expected(records, seqs)
    groups = {}
    for r in rows:
        if r["sha256"] is not None:
            groups.setdefault(r["sha256"], []).append(r)
    out = []
    for fp, members in groups.items():
        first = members[0]
        row = dict(first, sha256=fp, sightings=len(members), paths=len({m["path"] for m in members}),
                   first_seq=min(m["seq"] for m in members), first_path=members[0]["path"])
        if min_sightings is not None and row["sightings"] < min_sightings:
            continue
        if is_ca is not None and row["is_ca"] != is_ca:
            continue
        ok = all(filters.get(k) is None or row[k] == filters[k] for k in ("key_algorithm", "key_size", "signature_algorithm", "issuer"))
        if filters.get("fingerprint") and not fp.startswith(filters["fingerprint"].lower()):
            ok = False
        if filters.get("q") is not None:
            needle = folded(filters["q"])
            texts = [row["subject"], row["issuer"], row["serial_hex"], *row["san_values"]] + [m["path"] for m in members] + [m["filename"] for m in members]
            ok = ok and any(t is not None and needle in folded(t) for t in texts)
        if ok:
            out.append(row)
    return ordered(out, sort, direction, "sha256")


def random_records(rng, count, *, cert_count=6, path_count=5):
    """Random sightings with plenty of repeated fingerprints and repeated paths (for the duplicate invariants)."""
    paths = [f"C:\\r{p}\\f{p}.{ext}" for p in range(path_count) for ext in ("pem",)] + [f"D:\\r\\bundle{p}.pfx" for p in range(2)]
    records = []
    for _ in range(count):
        path = rng.choice(paths)
        records.append(pfx(path, rng.randint(1, cert_count), "root") if path.endswith(".pfx") else cert(path, rng.randint(1, cert_count), "root"))
    return records


def duplicate_counts(records, seqs=None):
    rows = expected(records, seqs)
    kinds = [r["duplicate_kind"] for r in rows]
    return {"within_file": kinds.count("within_file"), "across_files": kinds.count("across_files"),
            "sightings": sum(1 for r in rows if r["sha256"] is not None),
            "unique": len({r["sha256"] for r in rows if r["sha256"] is not None})}


# ------------------------------------------------------------------ the summary oracle (independent of backend/summaries.py)
import datetime as _dt
import math as _math

BUCKETS = ["expired", "0-30", "31-90", "91-365", "over-365"]


def bucket(days):
    if days < 0:
        return "expired"
    for limit, name in ((30, "0-30"), (90, "31-90"), (365, "91-365")):
        if days <= limit:
            return name
    return "over-365"


def _when(text):
    return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)


def assess_now(not_before, not_after, now, threshold):
    """(status, days, not_yet_valid) from first principles: seconds remaining, floored to whole days."""
    remaining = (_when(not_after) - now).total_seconds()
    days = _math.floor(remaining / 86400)
    status = "expired" if remaining < 0 else ("expiring" if days <= threshold else "valid")
    return status, days, _when(not_before) > now


def _nulls_first(*values):
    return tuple((v is not None, v) for v in values)


def ranked(groups, order, n, additive):
    ordered = sorted(groups, key=order)
    top, rest = ordered[:n], ordered[n:]
    other = None if not rest else {"groups": len(rest), **{m: sum(g[m] for g in rest) for m in additive}}
    return {"top": top, "other": other, "total_groups": len(groups), "limit": n}


def _group(rows, key_names, measure):
    """Group oracle rows (only those with a fingerprint unless `measure` says otherwise) by the given keys."""
    groups = {}
    for r in rows:
        groups.setdefault(tuple(r[k] for k in key_names), []).append(r)
    out = []
    for key, members in groups.items():
        item = dict(zip(key_names, key))
        item.update(measure(members))
        out.append(item)
    return out


def summary_oracle(records, now, *, threshold=30, top_n=20, seqs=None):
    rows = expected(records, seqs)
    with_cert = [r for r in rows if r["sha256"] is not None]
    unique_ids = {r["sha256"] for r in with_cert}
    kinds = [r["duplicate_kind"] for r in rows]
    # duplicates by the closed formulas (independent of the per-row labelling used for the kinds above)
    per_path, per_fp = {}, {}
    for r in with_cert:
        per_path[(r["sha256"], r["path"])] = per_path.get((r["sha256"], r["path"]), 0) + 1
        per_fp.setdefault(r["sha256"], set()).add(r["path"])
    within = sum(n - 1 for n in per_path.values())
    across = sum(len(paths) - 1 for paths in per_fp.values())
    assert (within, across) == (kinds.count("within_file"), kinds.count("across_files"))
    statuses = ("ok", "malformed", "unsupported", "too_large", "no_certificate", "access_denied", "read_error", "skipped")
    parse_status = {s: sum(1 for r in rows if r["parse_status"] == s) for s in statuses}
    formats = {f: sum(1 for r in rows if r["format"] == f) for f in ("pem", "der", "pkcs12", "unknown")}

    discovery = {s: sum(1 for r in with_cert if r["validity_status"] == s) for s in ("valid", "expiring", "expired")}
    discovery["not_yet_valid"] = sum(1 for r in with_cert if r["not_yet_valid"])
    discovery_buckets = {b: 0 for b in BUCKETS}
    for r in with_cert:
        discovery_buckets[bucket(r["days_to_expiry"])] += 1

    now_unique = {"valid": 0, "expiring": 0, "expired": 0, "not_yet_valid": 0}
    now_sightings, buckets_unique, buckets_sightings = dict(now_unique), {b: 0 for b in BUCKETS}, {b: 0 for b in BUCKETS}
    sightings_of = {}
    for r in with_cert:
        sightings_of[r["sha256"]] = sightings_of.get(r["sha256"], 0) + 1
    first_row = {}
    for r in with_cert:
        first_row.setdefault(r["sha256"], r)
    for sha, r in first_row.items():
        status, days, nyv = assess_now(r["not_before"], r["not_after"], now, threshold)
        for counts, buckets, weight in ((now_unique, buckets_unique, 1), (now_sightings, buckets_sightings, sightings_of[sha])):
            counts[status] += weight
            buckets[bucket(days)] += weight
            counts["not_yet_valid"] += weight if nyv else 0

    def cert_measure(members):
        return {"unique": len({m["sha256"] for m in members}), "sightings": len(members)}
    algorithms = ranked(_group(with_cert, ("key_algorithm", "key_size", "key_curve"), cert_measure),
                        lambda g: (-g["unique"], -g["sightings"], _nulls_first(g["key_algorithm"], g["key_size"], g["key_curve"])), top_n, ("unique", "sightings"))
    signatures = ranked(_group(with_cert, ("signature_algorithm",), cert_measure),
                        lambda g: (-g["unique"], -g["sightings"], g["signature_algorithm"]), top_n, ("unique", "sightings"))
    issuers = ranked(_group(with_cert, ("issuer",), cert_measure), lambda g: (-g["unique"], -g["sightings"], g["issuer"]), top_n, ("unique", "sightings"))
    roots = ranked(_group(rows, ("scan_root",), lambda m: {"observations": len(m), "sightings": sum(1 for x in m if x["sha256"]),
                                                            "unique": len({x["sha256"] for x in m if x["sha256"]})}),
                   lambda g: (-g["observations"], g["scan_root"]), 100, ("observations", "sightings"))
    for r in with_cert:
        r["directory"] = r["path"][:r["path"].rfind("\\") + 1]
    directories = ranked(_group(with_cert, ("directory",), lambda m: {"sightings": len(m), "unique": len({x["sha256"] for x in m})}),
                         lambda g: (-g["sightings"], -g["unique"], g["directory"]), top_n, ("sightings",))
    failures = ("malformed", "unsupported", "too_large", "access_denied", "read_error")
    return {"totals": {"records": len(rows), "sightings": len(with_cert), "unique_certificates": len(unique_ids),
                       "duplicate_observations": {"total": len(with_cert) - len(unique_ids), "within_file": within, "across_files": across},
                       "parse_failures": sum(parse_status[s] for s in failures), "no_certificate": parse_status["no_certificate"],
                       "skipped": parse_status["skipped"]},
            "parse_status": parse_status, "formats": formats,
            "validity": {"at_discovery": discovery, "now": {"unique": now_unique, "sightings": now_sightings}},
            "expiry_buckets": {"definitions": BUCKETS, "at_discovery": discovery_buckets,
                               "now": {"unique": buckets_unique, "sightings": buckets_sightings}},
            "algorithms": algorithms, "signature_algorithms": signatures, "issuers": issuers,
            "locations": {"scan_roots": roots, "directories": directories}}
