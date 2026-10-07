"""Unit tests for agent.pem: block location and base64 decoding."""
import base64
import time

import pytest

import pemgen
from agent.pem import PemError, decode_block, find_certificate_blocks, has_pem_marker

DER = pemgen.der_of("key_p256")


def bodies(data, max_blocks=1000):
    blocks, truncated = find_certificate_blocks(data, max_blocks)
    return blocks, truncated


@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r"])
@pytest.mark.parametrize("width", [1, 33, 64, 76, 100000])
def test_line_endings_and_widths(eol, width):
    blocks, truncated = bodies(pemgen.pem_encode(DER, width=width, eol=eol))
    assert not truncated and len(blocks) == 1 and blocks[0].error is None
    assert decode_block(blocks[0].body) == DER


def test_no_trailing_newline_bom_indentation_and_surrounding_text():
    pem = pemgen.pem_encode(DER, final_eol=False)
    for data in (
        pem,
        b"\xef\xbb\xbf" + pem,
        b"Bag Attributes\n    friendlyName: x\nsubject=/CN=x\n" + pem + b"\ntrailing words\n",
        b"    " + pem.replace(b"\n", b"\n    "),
        b"\t" + pem,
    ):
        blocks, _ = bodies(data)
        assert len(blocks) == 1 and decode_block(blocks[0].body) == DER


def test_whitespace_inside_body_is_tolerated():
    b64 = base64.b64encode(DER).decode()
    messy = "\n \t".join(b64[i:i + 20] for i in range(0, len(b64), 20))
    data = f"-----BEGIN CERTIFICATE-----\n{messy}\n\n-----END CERTIFICATE-----\n".encode()
    assert decode_block(bodies(data)[0][0].body) == DER


@pytest.mark.parametrize("label", [b"CERTIFICATE", b"X509 CERTIFICATE", b"TRUSTED CERTIFICATE"])
def test_accepted_labels(label):
    blocks, _ = bodies(pemgen.pem_encode(DER, label=label))
    assert len(blocks) == 1 and decode_block(blocks[0].body) == DER


@pytest.mark.parametrize("label", [b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST", b"X509 CRL",
                                   b"PKCS7", b"PUBLIC KEY", b"DH PARAMETERS", b"PRIVATE KEY"])
def test_other_labels_are_ignored(label):
    assert bodies(pemgen.pem_encode(DER, label=label))[0] == []
    mixed = pemgen.pem_encode(DER, label=label) + pemgen.pem_encode(DER)
    blocks, _ = bodies(mixed)
    assert len(blocks) == 1 and decode_block(blocks[0].body) == DER


def test_lowercase_or_malformed_markers_are_not_blocks():
    assert bodies(b"-----BEGIN certificate-----\nAAAA\n-----END certificate-----\n")[0] == []
    assert bodies(b"----BEGIN CERTIFICATE----\nAAAA\n----END CERTIFICATE----\n")[0] == []
    assert not has_pem_marker(b"nothing to see")


def test_marker_must_start_a_line():
    glued = b"text-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    assert bodies(glued)[0] == []


def test_multiple_blocks_keep_order():
    ders = [pemgen.der_of(n) for n in ("key_p256", "key_rsa2048", "key_ed25519")]
    data = b"junk\n".join(pemgen.pem_encode(d) for d in ders)
    blocks, _ = bodies(data)
    assert [decode_block(b.body) for b in blocks] == ders


def test_unterminated_block_at_eof():
    blocks, _ = bodies(b"-----BEGIN CERTIFICATE-----\nAAAA\n")
    assert [(b.body, b.error) for b in blocks] == [(None, "pem_unterminated_block")]


def test_unterminated_block_followed_by_valid_block():
    data = b"-----BEGIN CERTIFICATE-----\nAAAA\n" + pemgen.pem_encode(DER)
    blocks, _ = bodies(data)
    assert blocks[0].error == "pem_unterminated_block"
    assert blocks[1].error is None and decode_block(blocks[1].body) == DER


def test_label_mismatch():
    data = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END X509 CERTIFICATE-----\n"
    assert [b.error for b in bodies(data)[0]] == ["pem_label_mismatch"]


def test_stray_end_marker_is_ignored():
    assert bodies(b"-----END CERTIFICATE-----\n" + pemgen.pem_encode(DER))[0][0].error is None


def test_non_certificate_block_swallowing_a_marker_does_not_hide_following_certificate():
    data = b"-----BEGIN PRIVATE KEY-----\nAAAA\n" + pemgen.pem_encode(DER)       # key never terminated
    blocks, _ = bodies(data)
    assert len(blocks) == 1 and decode_block(blocks[0].body) == DER


def test_max_blocks_and_truncation_flag():
    data = b"".join(pemgen.pem_encode(DER) for _ in range(5))
    blocks, truncated = bodies(data, max_blocks=3)
    assert len(blocks) == 3 and truncated
    blocks, truncated = bodies(data, max_blocks=5)
    assert len(blocks) == 5 and not truncated


@pytest.mark.parametrize("body,code", [
    (b"", "pem_empty_body"), (b"  \n\t\n", "pem_empty_body"),
    (b"Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA", "pem_headers_unsupported"),
    (b"AAA*AAAA", "pem_bad_base64"), (b"AAAAA", "pem_bad_base64"),       # bad char / bad padding
    (b"AA=A", "pem_bad_base64"),
])
def test_decode_block_errors(body, code):
    with pytest.raises(PemError) as e:
        decode_block(body)
    assert e.value.code == code


def test_decode_block_size_cap():
    with pytest.raises(PemError) as e:
        decode_block(b"A" * 3_000_000)
    assert e.value.code == "pem_body_too_large"


def test_linear_time_with_many_markers():
    for data in (b"-----BEGIN FOO-----\n" * 100_000,
                 b"-----END FOO-----\n" * 100_000,
                 b"-----BEGIN CERTIFICATE-----\n" * 100_000,
                 (b"-----BEGIN FOO-----\nAAAA\n-----END FOO-----\n") * 50_000):
        start = time.perf_counter()
        bodies(data, max_blocks=1000)
        assert time.perf_counter() - start < 5.0
