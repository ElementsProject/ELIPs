import json

import pytest

from address import base32_decode, decode_address
from gen_vectors import VECTORS, generate
from hke import EncapsDerand, cbytes, expandDecapsulationKey
from key_derivation import derive_msk
from nonce import (
    decode_hke_nonce, decode_placeholder, recover_hke_seed,
    simplicity_nonce_hash_input,
)

V = json.loads(VECTORS.read_text())


def x(s: str) -> bytes:
    return bytes.fromhex(s)


def test_vectors_file_is_current():
    assert generate() == V


@pytest.mark.parametrize("v", V["valid"], ids=[v["comment"] for v in V["valid"]])
def test_valid(v):
    given, expected = v["given"], v["expected"]
    msk = derive_msk(x(given["mbk"]), x(given["scriptPubKey"]))
    assert msk == x(expected["msk"])

    (_, _, B, ek) = expandDecapsulationKey(msk)
    assert cbytes(B) == x(expected["B"])
    assert ek == x(expected["ek"])
    # The HKE blinding key differs from the SLIP-77 one.
    assert cbytes(B) != x(expected["slip77_B"])

    decoded = decode_address(expected["address"])
    assert decoded.B == cbytes(B)
    assert decoded.ek == ek
    assert decoded.script_pubkey() == x(given["scriptPubKey"])

    K, ciphertext = EncapsDerand(decoded.B, ek, int(given["e"], 16), x(given["m"]))
    assert ciphertext == (x(expected["E_bytes"]), x(expected["c"]))
    assert decode_hke_nonce(x(expected["hke_nonce"])) == ciphertext
    assert decode_placeholder(x(expected["placeholder"])) == (decoded.B, ek)
    assert recover_hke_seed(x(expected["hke_nonce"]), msk) == K == x(expected["K"])
    assert simplicity_nonce_hash_input(x(expected["hke_nonce"])) == x(expected["simplicity_nonce_hash_input"])


@pytest.mark.parametrize(
    "case", V["invalid_address"], ids=[c["comment"] for c in V["invalid_address"]]
)
def test_invalid(case):
    with pytest.raises(ValueError):
        decode_address(case["address"])


def test_valid_upper_case():
    address = V["valid"][0]["expected"]["address"]
    assert decode_address(address.upper()) == decode_address(address)


def test_crc_boundary_collision():
    """A 30-bit burst in the encoded byte order can evade this CRC format."""
    case = V["crc_collision"]
    original = base32_decode(V["valid"][0]["expected"]["address"].split("1", 1)[1])
    modified = base32_decode(case["address"].split("1", 1)[1])
    differing_bits = [
        i * 8 + bit
        for i, (a, b) in enumerate(zip(original, modified))
        for bit in range(8) if (a ^ b) & (1 << (7 - bit))
    ]
    assert max(differing_bits) - min(differing_bits) + 1 == 30
    decoded = decode_address(case["address"])
    assert decoded.B == x(case["expected"]["B"])
    assert decoded.ek == x(case["expected"]["ek"])
    assert decoded.program == x(case["expected"]["program"])
    assert decoded.program != x(V["valid"][0]["given"]["scriptPubKey"])[2:]


def test_single_character_checksum_error():
    case = next(c for c in V["invalid_address"] if c["comment"] == "single-character checksum error")
    with pytest.raises(ValueError, match="checksum"):
        decode_address(case["address"])
