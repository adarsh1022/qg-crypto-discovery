"""Small text-safety helpers shared by the ingestion code (pure, stdlib only).

Persistence is allow-list based: only named, typed, length-limited fields are ever stored. These
helpers add two cheap defences on top: text is made safe for strict UTF-8 storage, and anything that
looks like PEM armor is refused wherever free text is accepted.
"""
from __future__ import annotations

RAW_TOKENS = frozenset({"raw", "der", "pem", "secret", "password"})
RAW_PHRASES = ("private_key", "privatekey", "key_material")


def is_raw_material_name(name: str) -> bool:
    """True for names that would carry raw certificate/key material (key_algorithm, key_size, key_curve are fine)."""
    lowered = name.lower()
    return bool(set(lowered.split("_")) & RAW_TOKENS) or any(phrase in lowered for phrase in RAW_PHRASES)


def sanitize_text(text: str) -> str:
    """Make a string safe for strict UTF-8 storage: lone surrogates and NUL become visible escapes.

    Same rule as agent.observations.safe_text (U+D800 -> the six characters \\ud800), plus NUL, which
    SQLite handles badly inside text. Valid characters, including non-BMP ones, are untouched. Idempotent.
    """
    return text.encode("utf-8", "backslashreplace").decode("utf-8").replace("\x00", "\\x00")


def has_pem_armor(text: str) -> bool:
    return "-----BEGIN" in text or "-----END" in text
