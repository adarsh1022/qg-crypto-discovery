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
