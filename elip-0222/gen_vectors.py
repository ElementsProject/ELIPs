"""Generate `vectors.json`, the HKE test vectors.

All inputs are derived from fixed labels, so the output is reproducible:

    .venv/bin/python gen_vectors.py
"""

import hashlib
import json
from pathlib import Path

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_1024

from hke import (
    KEM,
    H_ecdh,
    HKEFailure,
    Decaps,
    EncapsDerand,
    G,
    cbytes,
    expandDecapsulationKey,
    lift,
    n,
)
from secp256k1lab.secp256k1 import FE  # importable once hke has set up the path

p = FE.SIZE

VECTORS = Path(__file__).with_name("vectors.json")


def label(s: str) -> bytes:
    return hashlib.sha256(b"ELIP-HKE/v1 test vector/" + s.encode()).digest()


def scalar(s: str) -> int:
    return int.from_bytes(label(s), "big") % (n - 1) + 1


def h(x: bytes) -> str:
    return x.hex()


def h32(x: int) -> str:
    return x.to_bytes(32, "big").hex()


def flip(data: bytes, i: int) -> bytes:
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1 :]


def set_coefficient(ek: bytes, i: int, value: int) -> bytes:
    """Overwrite the `i`-th 12-bit coefficient of `ek` (ByteEncode_12 layout)."""
    ek = bytearray(ek)
    j = 3 * (i // 2)
    if i % 2 == 0:
        ek[j] = value & 0xFF
        ek[j + 1] = (ek[j + 1] & 0xF0) | (value >> 8)
    else:
        ek[j + 1] = (ek[j + 1] & 0x0F) | ((value & 0x0F) << 4)
        ek[j + 2] = value >> 4
    return bytes(ek)


def ek_from_coefficients(coefficients: list[int], rho: bytes) -> bytes:
    """An `ek` with the given 768 coefficients, followed by `rho`."""
    ek = bytes(KEM.L_ek - 32) + rho
    for i, value in enumerate(coefficients):
        ek = set_coefficient(ek, i, value)
    return ek


def hybrid(P) -> bytes:
    """The 65-byte SEC1 hybrid encoding of `P`: prefix 0x06 or 0x07 by the parity of Y."""
    return bytes([6 + (int(P.y) & 1)]) + P.to_bytes_uncompressed()[1:]


def valid_vector(comment: str, msk: bytes, e: int, m: bytes) -> dict:
    (b, dk, B, ek) = expandDecapsulationKey(msk)
    K, (E_bytes, c) = EncapsDerand(cbytes(B), ek, e, m)
    assert Decaps((E_bytes, c), msk) == K
    return {
        "comment": comment,
        "given": {"msk": h(msk), "e": h32(e), "m": h(m)},
        "expected": {
            "b": h32(b),
            "B": h(cbytes(B)),
            "ek": h(ek),
            "dk": h(dk),
            "E_bytes": h(E_bytes),
            "c": h(c),
            "K_c": h(H_ecdh(cbytes(b * lift(E_bytes)))),
            "K_q": h(KEM.Decaps(dk, c)),
            "K": h(K),
        },
    }


def encaps_valid_vector(comment: str, B: bytes, ek: bytes, e: int, m: bytes) -> dict:
    K, (E_bytes, c) = EncapsDerand(B, ek, e, m)
    return {
        "comment": comment,
        "given": {"B": h(B), "ek": h(ek), "e": h32(e), "m": h(m)},
        "expected": {
            "E_bytes": h(E_bytes),
            "c": h(c),
            "K_c": h(H_ecdh(cbytes(e * lift(B)))),
            "K_q": h(KEM.Encaps_internal(ek, m)[0]),
            "K": h(K),
        },
    }


def rejection_vector(comment: str, msk: bytes, E_bytes: bytes, c: bytes, K_honest: str) -> dict:
    (b, dk, _, _) = expandDecapsulationKey(msk)
    K = Decaps((E_bytes, c), msk)
    assert h(K) != K_honest
    return {
        "comment": comment,
        "given": {"msk": h(msk), "E_bytes": h(E_bytes), "c": h(c)},
        "expected": {
            "K_c": h(H_ecdh(cbytes(b * lift(E_bytes)))),
            "K_q": h(KEM.Decaps(dk, c)),
            "K": h(K),
        },
    }


def decaps_failure_vector(comment: str, msk: bytes, E_bytes: bytes, c: bytes) -> dict:
    try:
        Decaps((E_bytes, c), msk)
    except HKEFailure:
        return {"comment": comment, "given": {"msk": h(msk), "E_bytes": h(E_bytes), "c": h(c)}}
    raise AssertionError(f"Decaps did not fail: {comment}")


def x_starts_with_zero(P) -> bool:
    return cbytes(P)[1] == 0


def encaps_failure_vector(comment: str, B: bytes, ek: bytes, e: int, m: bytes) -> dict:
    try:
        EncapsDerand(B, ek, e, m)
    except HKEFailure:
        return {"comment": comment, "given": {"B": h(B), "ek": h(ek), "e": h32(e), "m": h(m)}}
    raise AssertionError(f"EncapsDerand did not fail: {comment}")


def x_not_on_curve() -> bytes:
    X = 0
    while lift(b"\x02" + X.to_bytes(32, "big")) is not None:
        X += 1
    return b"\x02" + X.to_bytes(32, "big")


def x_ge_p() -> bytes:
    """A compressed encoding with X >= p whose X - p is a valid x coordinate,
    so an implementation that reduces X mod p instead of rejecting it accepts it."""
    X = p
    while lift(b"\x02" + (X - p).to_bytes(32, "big")) is None:
        X += 1
    return b"\x02" + X.to_bytes(32, "big")


def invalid_encodings(P_bytes: bytes) -> list[tuple[str, bytes]]:
    """Byte strings that `lift` must reject, each made from the valid encoding `P_bytes`."""
    P = lift(P_bytes)
    return [
        ("empty", b""),
        ("point at infinity (0x00)", b"\x00"),
        ("prefix 0x04", b"\x04" + P_bytes[1:]),
        ("uncompressed (65 bytes)", P.to_bytes_uncompressed()),
        ("hybrid (65 bytes)", hybrid(P)),
        ("32 bytes", P_bytes[:32]),
        ("34 bytes", P_bytes + b"\x00"),
        ("x = p + 1, which must not be reduced to the valid x = 1", x_ge_p()),
        ("x not on the curve", x_not_on_curve()),
        ("x only (32 bytes), the BIP340 encoding", P_bytes[1:]),
        ("33 zero bytes, which BIP327 decodes as the point at infinity", bytes(33)),
    ]


def generate() -> dict:
    msk = [label(f"msk/{i}") for i in range(3)]
    # Found by trying i = 0, 1, ...: the x coordinate of B, E and e*B, respectively,
    # starts with a zero byte, which an encoding of x in fewer than 32 bytes drops;
    # and K_c and K_q, respectively, start with a zero byte, which an implementation
    # that does not handle them as fixed 32-byte strings may lose.
    msk_lz = label("msk/844")
    e_lz_E = scalar("e/x(E)/1136")
    e_lz_eB = scalar("e/x(e*B)/167")
    e_lz_Kc = scalar("e/K_c/167")
    m_lz_Kq = label("m/K_q/100")
    assert x_starts_with_zero(expandDecapsulationKey(msk_lz)[2])
    assert x_starts_with_zero(e_lz_E * G)
    assert x_starts_with_zero(e_lz_eB * expandDecapsulationKey(msk[2])[2])
    assert H_ecdh(cbytes(e_lz_Kc * expandDecapsulationKey(msk[2])[2]))[0] == 0
    assert KEM.Encaps_internal(expandDecapsulationKey(msk[1])[3], m_lz_Kq)[0][0] == 0

    # KeyGen, EncapsDerand and Decaps end to end.
    valid = [
        valid_vector("pseudorandom inputs", msk[0], scalar("e/0"), label("m/0")),
        valid_vector("pseudorandom inputs, another recipient", msk[1], scalar("e/1"), label("m/1")),
        valid_vector("smallest e: e = 1, so E = G", msk[2], 1, label("m/2")),
        valid_vector("largest e: e = n - 1, so E = -G", msk[2], n - 1, label("m/3")),
        valid_vector("all-zero m", msk[0], scalar("e/4"), bytes(32)),
        valid_vector("x(B) starts with a zero byte", msk_lz, scalar("e/5"), label("m/5")),
        valid_vector("x(E) starts with a zero byte", msk[1], e_lz_E, label("m/6")),
        valid_vector("x(e*B) starts with a zero byte", msk[2], e_lz_eB, label("m/7")),
        valid_vector("K_c starts with a zero byte", msk[2], e_lz_Kc, label("m/8")),
        valid_vector("K_q starts with a zero byte", msk[1], scalar("e/9"), m_lz_Kq),
    ]

    # The other groups change the first valid vector, so read back its values.
    given0, expected0, expected1 = valid[0]["given"], valid[0]["expected"], valid[1]["expected"]
    e0, m0 = int(given0["e"], 16), bytes.fromhex(given0["m"])
    B0, ek0 = bytes.fromhex(expected0["B"]), bytes.fromhex(expected0["ek"])
    E0, c0, K0 = bytes.fromhex(expected0["E_bytes"]), bytes.fromhex(expected0["c"]), expected0["K"]
    E1, c1 = bytes.fromhex(expected1["E_bytes"]), bytes.fromhex(expected1["c"])

    # EncapsDerand alone, on an ek that KeyGen does not produce. Each 3-byte group packs
    # q - 1 = 0xd00 next to q - 2 = 0xcff, in both orders, so every bit that a misdecoded
    # q - 1 could pick up from its neighbour is one, and pushes it to q or more.
    q = KEM.q
    encaps_valid = [
        encaps_valid_vector(
            "largest valid ek: each 3-byte group packs q - 1 next to q - 2, rho is all 0xff",
            B0, ek_from_coefficients([q - 1, q - 2, q - 2, q - 1] * 192, b"\xff" * 32), e0, m0,
        ),
    ]

    # Decaps succeeds but returns a K unrelated to the sender's.
    def rejected(comment, E_bytes=E0, c=c0):
        return rejection_vector(comment, msk[0], E_bytes, c, K0)

    implicit_rejection = [
        rejected("first valid vector with the first bit of c flipped", c=flip(c0, 0)),
        rejected("first valid vector with a bit in the last byte of c flipped", c=flip(c0, KEM.L_c - 1)),
        rejected("first valid vector with E replaced by another valid point, 3*G", E_bytes=cbytes(3 * G)),
        rejected("first valid vector with E taken from the second valid vector", E_bytes=E1),
        rejected("second valid vector decapsulated by the first recipient", E_bytes=E1, c=c1),
    ]

    # Decaps must fail.
    def decaps_fails(comment, E_bytes=E0, c=c0):
        return decaps_failure_vector(comment, msk[0], E_bytes, c)

    decaps_failure = [
        *(decaps_fails(f"E_bytes: {what}", E_bytes=bad) for what, bad in invalid_encodings(E0)),
        decaps_fails("c: one byte short", c=c0[:-1]),
        decaps_fails("c: one byte too long", c=c0 + b"\x00"),
    ]

    # EncapsDerand must fail.
    def encaps_fails(comment, B=B0, ek=ek0, e=e0, m=m0):
        return encaps_failure_vector(comment, B, ek, e, m)

    # Valid keys of the other ML-KEM parameter sets, which an implementation that
    # picks the parameter set from |ek| would accept.
    ek_512 = ML_KEM_512._keygen_internal(label("ML-KEM-512/d"), label("ML-KEM-512/z"))[0]
    ek_1024 = ML_KEM_1024._keygen_internal(label("ML-KEM-1024/d"), label("ML-KEM-1024/z"))[0]

    def coefficient(i, value):
        return set_coefficient(ek0, i, value)

    encaps_failure = [
        encaps_fails("ek: coefficient 0 = q (first half of a 3-byte group)", ek=coefficient(0, q)),
        encaps_fails("ek: coefficient 0 = 4095, the largest 12-bit value", ek=coefficient(0, 4095)),
        encaps_fails("ek: coefficient 1 = q (second half of a 3-byte group)", ek=coefficient(1, q)),
        encaps_fails("ek: coefficient 1 = 4095, the largest 12-bit value", ek=coefficient(1, 4095)),
        encaps_fails("ek: coefficient 255 = q (last of polynomial 0)", ek=coefficient(255, q)),
        encaps_fails("ek: coefficient 256 = q (first of polynomial 1)", ek=coefficient(256, q)),
        encaps_fails("ek: coefficient 511 = q (last of polynomial 1)", ek=coefficient(511, q)),
        encaps_fails("ek: coefficient 512 = q (first of polynomial 2)", ek=coefficient(512, q)),
        encaps_fails("ek: coefficient 767 = q (last of polynomial 2)", ek=coefficient(767, q)),
        encaps_fails("ek: one byte short", ek=ek0[:-1]),
        encaps_fails("ek: one byte too long", ek=ek0 + b"\x00"),
        encaps_fails("ek: a valid ML-KEM-512 key (800 bytes)", ek=ek_512),
        encaps_fails("ek: a valid ML-KEM-1024 key (1568 bytes)", ek=ek_1024),
        *(encaps_fails(f"B: {what}", B=bad) for what, bad in invalid_encodings(B0)),
        encaps_fails("e: 0", e=0),
        encaps_fails("e: n, the group order", e=n),
        encaps_fails("e: n + 1, which must not be reduced to e = 1", e=n + 1),
        encaps_fails("e: 2^256 - 1, the largest 32-byte value", e=2**256 - 1),
        encaps_fails("m: one byte short", m=m0[:-1]),
        encaps_fails("m: one byte too long", m=m0 + b"\x00"),
    ]

    return {
        "scheme": "ELIP-HKE/v1",
        "encoding": "byte strings and scalars are lowercase hex; scalars are 32-byte big-endian",
        "layout": "each vector has the inputs in given and the values to compute in expected; *_failure vectors have no expected, the call must fail",
        "valid": valid,
        "encaps_valid": encaps_valid,
        "implicit_rejection": implicit_rejection,
        "decaps_failure": decaps_failure,
        "encaps_failure": encaps_failure,
    }


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"wrote {VECTORS}")
