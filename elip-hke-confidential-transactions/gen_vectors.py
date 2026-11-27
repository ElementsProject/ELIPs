"""Generate `vectors.json`, the test vectors for `elip-hke-confidential-transactions.mediawiki`'s key
derivation, HKE confidential address and nonce encoding.

All inputs are derived from fixed labels, so the output is reproducible:

    .venv/bin/python gen_vectors.py
"""

import hashlib
import json
from pathlib import Path

from hke import KEM, EncapsDerand, cbytes, expandDecapsulationKey, G, n
from address import (
    HKE_VERSION, HRP, HKEConfidentialAddress, base32_decode, base32_encode, crc32,
    witness_script_pubkey,
)
from blech32m import CHARSET
from key_derivation import derive_msk, slip77_blinding_key
from nonce import encode_hke_nonce, encode_placeholder, simplicity_nonce_hash_input

VECTORS = Path(__file__).with_name("vectors.json")


def label(s: str) -> bytes:
    return hashlib.sha256(b"ELIP-HKE-CT/v1 test vector/" + s.encode()).digest()


def vector(comment: str, mbk: bytes, witver: int, program: bytes) -> dict:
    spk = witness_script_pubkey(witver, program)
    msk = derive_msk(mbk, spk)
    (_, _, B, ek) = expandDecapsulationKey(msk)
    b_slip77 = int.from_bytes(slip77_blinding_key(mbk, spk), "big")
    assert 0 < b_slip77 < n
    # Fixed randomness is for test vectors only.
    e = 1 + int.from_bytes(label(comment + "/e"), "big") % (n - 1)
    m = label(comment + "/m")
    K, (E_bytes, c) = EncapsDerand(cbytes(B), ek, e, m)
    nonce = encode_hke_nonce(E_bytes, c)
    return {
        "comment": comment,
        "given": {
            "mbk": mbk.hex(), "scriptPubKey": spk.hex(),
            "e": e.to_bytes(32, "big").hex(), "m": m.hex(),
        },
        "expected": {
            "slip77_B": cbytes(b_slip77 * G).hex(),
            "msk": msk.hex(),
            "B": cbytes(B).hex(),
            "ek": ek.hex(),
            "address": HKEConfidentialAddress(B=cbytes(B), ek=ek, witver=witver, program=program).encode(),
            "E_bytes": E_bytes.hex(),
            "c": c.hex(),
            "K": K.hex(),
            "hke_nonce": nonce.hex(),
            "placeholder": encode_placeholder(cbytes(B), ek).hex(),
            "simplicity_nonce_hash_input": simplicity_nonce_hash_input(nonce).hex(),
        },
    }


def encode_raw(payload: bytes, hrp: str = HRP) -> str:
    """Encode an arbitrary payload with a valid checksum, bypassing the checks."""
    return hrp + "1" + base32_encode(payload + crc32(hrp, payload))


def payload_of(v: dict, witver=None, B=None, ek=None, program=None) -> bytes:
    """Payload of vector `v`, with any field optionally replaced."""
    spk = bytes.fromhex(v["given"]["scriptPubKey"])
    if witver is None:
        witver = 0 if spk[0] == 0 else spk[0] - 0x50
    if program is None:
        program = spk[2:]
    return (
        bytes([HKE_VERSION, witver])
        + (bytes.fromhex(v["expected"]["B"]) if B is None else B)
        + (bytes.fromhex(v["expected"]["ek"]) if ek is None else ek)
        + program
    )


BAD_EK = bytes([0xFF, 0xFF]) + bytes(KEM.L_ek - 2)  # first coefficient 0xFFF >= q


def invalid_addresses(v0: dict) -> list:
    """Strings a decoder for HRP `el2` MUST reject, each for one rule of the ELIP."""
    address = v0["expected"]["address"]
    flip = lambda s, i: s[:i] + CHARSET[CHARSET.index(s[i]) ^ 1] + s[i + 1:]
    cases = [
        ("unknown hke_version", encode_raw(bytes([0x02]) + payload_of(v0)[1:])),
        ("B not on curve", encode_raw(payload_of(v0, B=bytes([0x02]) + bytes(32)))),
        ("ek fails CheckEK", encode_raw(payload_of(v0, ek=BAD_EK))),
        ("witness version 17", encode_raw(payload_of(v0, witver=17))),
        ("v0 program of 25 bytes", encode_raw(payload_of(v0, program=bytes(25)))),
        ("program of 1 byte", encode_raw(payload_of(v0, witver=1, program=bytes(1)))),
        ("program of 41 bytes", encode_raw(payload_of(v0, witver=1, program=bytes(41)))),
        ("truncated ek", encode_raw(payload_of(v0)[: 2 + 33 + KEM.L_ek - 1])),
        ("other network HRP", encode_raw(payload_of(v0), hrp="tlq2")),
        ("mixed case", address[0].upper() + address[1:]),
        ("five or more padding bits", address + "q"),
        ("nonzero padding", flip(address, len(address) - 1)),
        ("single-character checksum error", flip(address, len(address) - 4)),
        ("missing separator", address.replace("1", "", 1)),  # the bech32 alphabet has no "1"
        ("character outside the alphabet", address[:-2] + "b" + address[-1]),
    ]
    return [{"comment": c, "address": a} for c, a in cases]


def crc_collision(v0: dict) -> dict:
    """A valid address differing from `v0` in a 30-bit burst across the payload/checksum boundary."""
    raw = bytearray(base32_decode(v0["expected"]["address"].split("1", 1)[1]))
    for i, mask in enumerate(bytes.fromhex("61d8f4ee")):  # last two payload, first two checksum bytes
        raw[len(raw) - 6 + i] ^= mask
    assert crc32(HRP, bytes(raw[:-4])) == bytes(raw[-4:])
    payload = bytes(raw[:-4])
    return {
        "comment": "CRC-32 collision: 30-bit burst across the payload/checksum boundary; decodes to another program",
        "address": HRP + "1" + base32_encode(bytes(raw)),
        "expected": {
            "B": payload[2:35].hex(),
            "ek": payload[35:35 + KEM.L_ek].hex(),
            "program": payload[35 + KEM.L_ek:].hex(),
        },
    }


def generate() -> dict:
    mbk = label("mbk")
    valid = [
        vector("P2WPKH", mbk, 0, label("p2wpkh")[:20]),
        vector("P2WSH", mbk, 0, label("p2wsh")),
        vector("P2TR", mbk, 1, label("p2tr")),
        vector("P2WPKH, other mbk", label("mbk 2"), 0, label("p2wpkh")[:20]),
    ]
    return {
        "valid": valid,
        "invalid_address": invalid_addresses(valid[0]),
        "crc_collision": crc_collision(valid[0]),
    }


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"wrote {VECTORS}")
