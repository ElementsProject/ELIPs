from io import BytesIO

import hke
import pytest

from nonce import (
    decode_hke_nonce, decode_placeholder, encode_hke_nonce, encode_placeholder,
    parse_nonce, read_nonce, recover_hke_seed, simplicity_nonce_hash_input,
    validate_output_nonce,
)


@pytest.mark.parametrize("prefix,length", [(0, 1), (1, 33), (2, 33), (3, 33),
                                         (4, 1121), (5, 1121), (6, 1217), (7, 1217)])
def test_field_boundaries(prefix, length):
    raw = bytes([prefix]) + bytes(length - 1)
    next_field = bytes.fromhex("160014")
    stream = BytesIO(raw + next_field)
    assert read_nonce(stream) == raw
    assert stream.read() == next_field
    assert parse_nonce(raw) == raw
    for malformed in (raw[:-1], raw + b"\x00"):
        with pytest.raises(ValueError):
            parse_nonce(malformed)


def test_unknown_prefixes():
    # Value/asset commitment tags are not nonce tags, nor are SEC1 65-byte keys.
    for prefix in range(8, 256):
        with pytest.raises(ValueError, match="prefix"):
            parse_nonce(bytes([prefix]) + bytes(32))
    for prefix in (4, 6, 7):
        with pytest.raises(ValueError, match="truncated"):
            parse_nonce(bytes([prefix]) + bytes(64))


@pytest.mark.parametrize("scalar", [1, hke.n - 1], ids=["even Y", "odd Y"])
def test_point_projection_and_placeholder(scalar):
    point = hke.cbytes(scalar * hke.G)
    c, ek = bytes(hke.L_c), bytes(hke.L_ek)
    nonce = encode_hke_nonce(point, c)
    placeholder = encode_placeholder(point, ek)
    assert len(nonce) == 1121 and nonce[0] == point[0] + 2
    assert len(placeholder) == 1217 and placeholder[0] == point[0] + 4
    assert decode_hke_nonce(nonce) == (point, c)
    assert decode_placeholder(placeholder) == (point, ek)
    assert hke.lift(decode_hke_nonce(nonce)[0]) == scalar * hke.G
    with pytest.raises(ValueError):
        decode_hke_nonce(placeholder)
    with pytest.raises(ValueError):
        decode_placeholder(nonce)


def test_encoder_rejects_wrong_shapes():
    point = hke.cbytes(hke.G)
    for encode, length in ((encode_hke_nonce, hke.L_c), (encode_placeholder, hke.L_ek)):
        for bad_point in (b"", point[:-1], b"\x04" + point[1:], point + bytes(32)):
            with pytest.raises(ValueError):
                encode(bad_point, bytes(length))
        for bad_length in (length - 1, length + 1):
            with pytest.raises(ValueError):
                encode(point, bytes(bad_length))


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("explicit", [False, True])
def test_output_validity(active, explicit):
    for prefix, length in ((0, 1), (1, 33), (2, 33), (3, 33),
                           (4, 1121), (5, 1121), (6, 1217), (7, 1217)):
        raw = bytes([prefix]) + bytes(length - 1)
        if prefix >= 6 or (prefix in (4, 5) and (not active or explicit)):
            with pytest.raises(ValueError):
                validate_output_nonce(raw, hke_active=active, explicit_value=explicit)
        else:
            validate_output_nonce(raw, hke_active=active, explicit_value=explicit)


def test_hash_commits_to_ciphertext_and_preserves_old_encodings():
    point = hke.cbytes(hke.G)
    a = encode_hke_nonce(point, bytes(hke.L_c))
    b = encode_hke_nonce(point, bytes(hke.L_c - 1) + b"\x01")
    assert decode_hke_nonce(a)[0] == decode_hke_nonce(b)[0]
    assert len(simplicity_nonce_hash_input(a)) == 65
    assert simplicity_nonce_hash_input(a) != simplicity_nonce_hash_input(b)
    for raw in (b"\x00", b"\x01" + bytes(32), point, hke.cbytes((hke.n - 1) * hke.G)):
        assert simplicity_nonce_hash_input(raw) == raw
    with pytest.raises(ValueError):
        simplicity_nonce_hash_input(encode_placeholder(point, bytes(hke.L_ek)))


def test_invalid_point_is_consensus_valid_but_unrecoverable():
    raw = b"\x04" + bytes(32 + hke.L_c)
    validate_output_nonce(raw, hke_active=True, explicit_value=False)
    assert recover_hke_seed(raw, bytes(32)) is None
    assert recover_hke_seed(raw[:-1], bytes(32)) is None


def test_modified_ciphertext_returns_a_different_seed():
    msk = bytes(32)
    _, _, B, ek = hke.expandDecapsulationKey(msk)
    K, (E_bytes, c) = hke.EncapsDerand(hke.cbytes(B), ek, 1, bytes(32))
    modified = bytes([c[0] ^ 1]) + c[1:]
    assert recover_hke_seed(encode_hke_nonce(E_bytes, c), msk) == K
    assert recover_hke_seed(encode_hke_nonce(E_bytes, modified), msk) != K


def test_local_failures_are_not_hidden(monkeypatch):
    raw = encode_hke_nonce(hke.cbytes(hke.G), bytes(hke.L_c))
    with pytest.raises(ValueError, match="msk"):
        recover_hke_seed(raw, b"")

    def fail(_):
        raise hke.HKEFailure("local derivation failure")

    monkeypatch.setattr(hke, "expandDecapsulationKey", fail)
    with pytest.raises(hke.HKEFailure, match="local derivation"):
        recover_hke_seed(raw, bytes(32))
