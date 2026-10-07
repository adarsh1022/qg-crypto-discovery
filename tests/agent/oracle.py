"""Compare our stdlib parser with `cryptography` (the test oracle) for one certificate.

`cryptography` is never imported by the agent; it only judges the agent here.
"""
from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

_CURVE_NAMES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521",
                "secp224r1": "P-224", "secp192r1": "P-192"}
_GN_TYPES = ((x509.DNSName, "dns"), (x509.RFC822Name, "email"),
             (x509.UniformResourceIdentifier, "uri"), (x509.IPAddress, "ip"),
             (x509.DirectoryName, "dir_name"), (x509.OtherName, "other_name"),
             (x509.RegisteredID, "registered_id"))


def load(der: bytes):
    """Oracle's view of the certificate, or None if the oracle itself rejects it."""
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError:
        return None


def _san_expected(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    out = []
    for gn in ext.value:
        for cls, label in _GN_TYPES:
            if isinstance(gn, cls):
                if label == "dir_name":
                    value = gn.value.rfc4514_string()
                elif label == "other_name":
                    value = gn.type_id.dotted_string
                elif label == "registered_id":
                    value = gn.value.dotted_string
                else:
                    value = str(gn.value)
                out.append((label, value))
                break
        else:
            out.append(("?", repr(gn)))
    return out


def compare(info, der: bytes, cert=None) -> tuple[list[str], list[str]]:
    """-> (mismatches, skipped). Empty `mismatches` means full agreement on everything compared.

    `skipped` lists comparisons the oracle could not make (e.g. unsupported key type); they are
    counted by the corpus test so the coverage gap is visible rather than silent.
    """
    cert = cert or x509.load_der_x509_certificate(der)
    bad: list[str] = []
    skipped: list[str] = []

    def eq(label, ours, theirs):
        if ours != theirs:
            bad.append(f"{label}: ours={ours!r} oracle={theirs!r}")

    eq("sha256", info.sha256, cert.fingerprint(hashes.SHA256()).hex())
    eq("serial", int(info.serial_hex, 16), cert.serial_number)
    eq("version", info.version, cert.version.value + 1)
    eq("subject", info.subject, cert.subject.rfc4514_string())
    eq("issuer", info.issuer, cert.issuer.rfc4514_string())
    eq("not_before", info.not_before, cert.not_valid_before_utc)
    eq("not_after", info.not_after, cert.not_valid_after_utc)
    eq("signature_oid", info.signature_algorithm_oid, cert.signature_algorithm_oid.dotted_string)
    eq("key_oid", info.key_algorithm_oid, cert.public_key_algorithm_oid.dotted_string)
    eq("self_issued", info.is_self_issued, cert.subject == cert.issuer)

    try:
        pk = cert.public_key()
    except (UnsupportedAlgorithm, ValueError):
        skipped.append("public_key")
    else:
        if isinstance(pk, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
            eq("key_size", info.key_size, pk.key_size)
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            eq("key_size", info.key_size, pk.curve.key_size)
            eq("key_curve", info.key_curve, _CURVE_NAMES.get(pk.curve.name, pk.curve.name))
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            eq("key_size", info.key_size, 256)
        elif isinstance(pk, ed448.Ed448PublicKey):
            eq("key_size", info.key_size, 456)
        elif isinstance(pk, x25519.X25519PublicKey):
            eq("key_size", info.key_size, 256)
        elif isinstance(pk, x448.X448PublicKey):
            eq("key_size", info.key_size, 448)
        else:
            skipped.append("key_size")

    try:
        eq("san", [(s.type, s.value) for s in info.san], _san_expected(cert))
    except (ValueError, x509.UnsupportedGeneralNameType):
        skipped.append("san")

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        eq("is_ca", info.is_ca, bc.ca)
        eq("path_length", info.path_length, bc.path_length)
    except x509.ExtensionNotFound:
        eq("is_ca", info.is_ca, None)
        eq("path_length", info.path_length, None)
    except ValueError:
        skipped.append("basic_constraints")
    return bad, skipped
