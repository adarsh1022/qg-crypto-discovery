"""OID -> name tables used by the X.509 parser. Pure data, no logic.

Names follow OpenSSL / NIST conventions so they read naturally in reports.
Anything not listed here is reported by its dotted OID and flagged with a warning;
it is never guessed.

Post-quantum OIDs (ML-DSA, ML-KEM, SLH-DSA) are taken from the NIST CSOR registry.
They cannot be cross-checked against the `cryptography` test oracle.
"""

# ---------------------------------------------------------------- signature algorithms
RSASSA_PSS = "1.2.840.113549.1.1.10"

SIGNATURE_ALGORITHMS = {
    # RSA PKCS#1 v1.5
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.3.14.3.2.29": "sha1WithRSA",
    RSASSA_PSS: "RSASSA-PSS",
    # ECDSA
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    # DSA
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    # SHA-3 variants
    "2.16.840.1.101.3.4.3.5": "dsa-with-sha3-224",
    "2.16.840.1.101.3.4.3.6": "dsa-with-sha3-256",
    "2.16.840.1.101.3.4.3.7": "dsa-with-sha3-384",
    "2.16.840.1.101.3.4.3.8": "dsa-with-sha3-512",
    "2.16.840.1.101.3.4.3.9": "ecdsa-with-SHA3-224",
    "2.16.840.1.101.3.4.3.10": "ecdsa-with-SHA3-256",
    "2.16.840.1.101.3.4.3.11": "ecdsa-with-SHA3-384",
    "2.16.840.1.101.3.4.3.12": "ecdsa-with-SHA3-512",
    "2.16.840.1.101.3.4.3.13": "RSA-SHA3-224",
    "2.16.840.1.101.3.4.3.14": "RSA-SHA3-256",
    "2.16.840.1.101.3.4.3.15": "RSA-SHA3-384",
    "2.16.840.1.101.3.4.3.16": "RSA-SHA3-512",
    # EdDSA
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # Post-quantum signatures (FIPS 204 / FIPS 205)
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
    "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
    "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
    "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
    "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
    "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
    "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

# ---------------------------------------------------------------- public key algorithms
RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
DSA = "1.2.840.10040.4.1"

PUBLIC_KEY_ALGORITHMS = {
    RSA_ENCRYPTION: "RSA",
    RSASSA_PSS: "RSASSA-PSS",
    EC_PUBLIC_KEY: "EC",
    DSA: "DSA",
    "1.2.840.113549.1.3.1": "DH",
    "1.2.840.10046.2.1": "DH",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
}
# SLH-DSA / ML-DSA public keys share their signature OIDs
for _oid, _name in SIGNATURE_ALGORITHMS.items():
    if _name.startswith(("ML-DSA", "SLH-DSA")):
        PUBLIC_KEY_ALGORITHMS[_oid] = _name

# Key algorithms whose size is fixed by the algorithm itself (bits).
FIXED_KEY_SIZES = {
    "1.3.101.110": 256,   # X25519
    "1.3.101.111": 448,   # X448
    "1.3.101.112": 256,   # Ed25519
    "1.3.101.113": 456,   # Ed448 (matches cryptography's key_size)
}

# ---------------------------------------------------------------- named EC curves -> (name, bits)
CURVES = {
    "1.2.840.10045.3.1.1": ("P-192", 192),
    "1.3.132.0.33": ("P-224", 224),
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.31": ("secp192k1", 192),
    "1.3.132.0.32": ("secp224k1", 224),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.36.3.3.2.8.1.1.3": ("brainpoolP192r1", 192),
    "1.3.36.3.3.2.8.1.1.5": ("brainpoolP224r1", 224),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 256),
    "1.3.36.3.3.2.8.1.1.9": ("brainpoolP320r1", 320),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 384),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 512),
}

# ---------------------------------------------------------------- hash algorithms (for RSASSA-PSS parameters)
HASHES = {
    "1.2.840.113549.2.5": "MD5",
    "1.3.14.3.2.26": "SHA-1",
    "2.16.840.1.101.3.4.2.4": "SHA-224",
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "2.16.840.1.101.3.4.2.5": "SHA-512/224",
    "2.16.840.1.101.3.4.2.6": "SHA-512/256",
    "2.16.840.1.101.3.4.2.7": "SHA3-224",
    "2.16.840.1.101.3.4.2.8": "SHA3-256",
    "2.16.840.1.101.3.4.2.9": "SHA3-384",
    "2.16.840.1.101.3.4.2.10": "SHA3-512",
}

# ---------------------------------------------------------------- distinguished-name attributes
# Deliberately the RFC 4514 short-name set only. Any other attribute type is rendered as its
# dotted OID (e.g. "1.2.840.113549.1.9.1=a@b.c"), which is also what `cryptography` does, so
# the two can be compared string-for-string.
NAME_ATTRIBUTES_RFC4514 = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.1": "UID",
    "0.9.2342.19200300.100.1.25": "DC",
}

# ---------------------------------------------------------------- extensions we decode
EXT_SUBJECT_ALT_NAME = "2.5.29.17"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
