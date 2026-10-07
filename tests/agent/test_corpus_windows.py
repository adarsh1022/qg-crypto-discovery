"""Real-world corpus: every certificate in the Windows ROOT and CA stores.

~330 certificates issued by hundreds of CAs over decades: v1 and v3, UTCTime and
GeneralizedTime, PrintableString/UTF8/T61/BMP names, old and new algorithms. Read via the
stdlib `ssl.enum_certificates` (read-only), so nothing is installed or written.

Rules:
  * our parser must accept every certificate in the store;
  * wherever the oracle can judge, we must agree with it exactly;
  * certificates the oracle itself rejects are counted and reported, not hidden.
"""
import hashlib
import ssl
import sys

import pytest

import oracle
from agent.x509_parse import parse_certificate

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows certificate store only")


def _store_certs():
    seen = {}
    for store in ("ROOT", "CA"):
        for der, encoding, _trust in ssl.enum_certificates(store):
            if encoding == "x509_asn":
                seen.setdefault(hashlib.sha256(der).hexdigest(), (store, bytes(der)))
    return seen


@pytest.fixture(scope="module")
def corpus():
    return _store_certs()


def test_corpus_is_substantial(corpus):
    assert len(corpus) >= 100, f"only {len(corpus)} certificates in the store; corpus too small to mean much"


def test_every_store_certificate_parses_and_agrees_with_oracle(corpus, capsys):
    ours_failed, mismatched, oracle_rejected, skipped_counts = [], [], [], {}
    compared = 0
    fingerprints = set()
    warning_counts: dict[str, int] = {}
    stats = {"v1": 0, "v3": 0, "warnings": 0, "ec": 0, "rsa": 0, "other_key": 0}

    for fp, (store, der) in corpus.items():
        try:
            info = parse_certificate(der)
        except Exception as e:                               # noqa: BLE001 - report all
            ours_failed.append((store, fp[:16], repr(e)))
            continue
        fingerprints.add(info.sha256)
        stats["v1" if info.version == 1 else "v3"] += (info.version in (1, 3))
        stats["warnings"] += bool(info.warnings)
        for w in info.warnings:
            warning_counts[w] = warning_counts.get(w, 0) + 1
        stats["ec" if info.key_algorithm == "EC" else "rsa" if info.key_algorithm == "RSA"
              else "other_key"] += 1
        assert info.sha256 == fp, "fingerprint must equal SHA-256 of the exact store bytes"

        cert = oracle.load(der)
        if cert is None:
            oracle_rejected.append((store, fp[:16], info.subject[:60]))
            continue
        bad, skipped = oracle.compare(info, der, cert)
        compared += 1
        for s in skipped:
            skipped_counts[s] = skipped_counts.get(s, 0) + 1
        if bad:
            mismatched.append((store, fp[:16], info.subject[:50], bad))

    with capsys.disabled():
        print(f"\n[corpus] certificates={len(corpus)} compared_with_oracle={compared} "
              f"oracle_rejected={len(oracle_rejected)} ours_failed={len(ours_failed)} "
              f"mismatched={len(mismatched)} oracle_skips={skipped_counts}")
        print(f"[corpus] v1={stats['v1']} v3={stats['v3']} rsa={stats['rsa']} ec={stats['ec']} "
              f"other_keys={stats['other_key']} with_warnings={stats['warnings']}")
        print(f"[corpus] warnings={warning_counts}")
        for row in oracle_rejected:
            print("[corpus] oracle rejected:", row)

    assert not ours_failed, f"our parser rejected store certificates: {ours_failed}"
    # Known, understood real-world defects only; a new warning type must be looked at, not ignored.
    known = {"serial_not_positive", "rsa_modulus_encoded_as_negative"}
    assert set(warning_counts) <= known, f"unexpected warning types: {set(warning_counts) - known}"
    assert not mismatched, "\n".join(f"{m[:3]}: {m[3]}" for m in mismatched)
    assert compared >= 0.95 * len(corpus), "oracle could judge too few certificates to be convincing"
