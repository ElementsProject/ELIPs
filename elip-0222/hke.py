"""Reference implementation of HKE (`elip-0222.mediawiki`, Specification).

Every function below corresponds one-to-one to a definition in the ELIP and
keeps its name, argument order and step order, so the code can be read side by
side with the pseudocode. A step that the pseudocode writes as "fail" raises
`HKEFailure`.

secp256k1 and the BIP340 tagged hash come from a vendored copy of
secp256k1lab (`secp256k1lab/`), as in the BIP-352 and BIP-374 reference
implementations. ML-KEM-768 comes from `kyber-py`, which `test_mlkem_acvp.py`
checks against NIST's ACVP test vectors for FIPS 203. Neither is constant time:
this is a reference for checking the specification, not for handling real
secrets.
"""

import secrets
import sys
from pathlib import Path

from kyber_py.ml_kem import ML_KEM_768 as _ML_KEM_768

# Prefer the vendored copy of secp256k1lab
sys.path.insert(0, str(Path(__file__).parent / "secp256k1lab/src"))
from secp256k1lab.secp256k1 import FE, G, GE  # noqa: E402
from secp256k1lab.util import tagged_hash  # noqa: E402

p = FE.SIZE
n = GE.ORDER
O = GE()  # point at infinity


class HKEFailure(Exception):
    """A step of the pseudocode that reads "fail"."""


# --- Notation ---------------------------------------------------------------


def cbytes(P: GE) -> bytes:
    """`cbytes(P)`: the 33-byte compressed SEC1 encoding of `P`."""
    return P.to_bytes_compressed()


def int_(x: bytes) -> int:
    """`int(x)`: the integer with big-endian encoding `x`."""
    return int.from_bytes(x, "big")


def lift(x: bytes):
    """`lift(x)`: the point whose compressed encoding is `x`.

    Returns `None` (failure) unless `|x| = 33`, `x[0]` is `0x02` or `0x03`,
    `int(x[1:33]) < p`, and that X coordinate is on the curve. Each check is
    explicit here; `GE.from_bytes_compressed` would also reject a bad prefix or
    `X >= p`, but asserts on the length rather than raising.
    """
    if len(x) != 33 or x[0] not in (2, 3) or int_(x[1:]) >= p:
        return None
    try:
        return GE.from_bytes_compressed(x)
    except ValueError:
        return None


def H(tag: str, x: bytes) -> bytes:
    """Tagged hash `H_t(x) = SHA256(SHA256(t) || SHA256(t) || x)` (BIP340)."""
    return tagged_hash(tag, x)


def H_blind(x: bytes) -> bytes:
    return H("ELIP-HKE/v1/blind", x)


def H_kem_d(x: bytes) -> bytes:
    return H("ELIP-HKE/v1/kem-d", x)


def H_kem_z(x: bytes) -> bytes:
    return H("ELIP-HKE/v1/kem-z", x)


def H_ecdh(x: bytes) -> bytes:
    return H("ELIP-HKE/v1/ecdh", x)


def H_seed(x: bytes) -> bytes:
    return H("ELIP-HKE/v1/seed/ML-KEM-768", x)


# --- KEM interface ----------------------------------------------------------


class KEM:
    """The ELIP's KEM interface, instantiated with ML-KEM-768 (FIPS 203)."""

    L_ek = 1184
    L_c = 1088
    q = 3329

    @staticmethod
    def KeyGen_internal(d: bytes, z: bytes):
        """`KeyGen_internal(d, z) -> (ek, dk)` (FIPS 203, Algorithm 16)."""
        return _ML_KEM_768._keygen_internal(d, z)

    @staticmethod
    def Encaps_internal(ek: bytes, m: bytes):
        """`Encaps_internal(ek, m) -> (K_q, c)` (FIPS 203, Algorithm 17)."""
        return _ML_KEM_768._encaps_internal(ek, m)

    @staticmethod
    def Decaps(dk: bytes, c: bytes) -> bytes:
        """`Decaps(dk, c) -> K_q` (FIPS 203, Algorithm 21).

        Uses implicit rejection: a well-formed `c` that was not produced for
        this key yields a pseudorandom `K_q` instead of an error.
        """
        return _ML_KEM_768.decaps(dk, c)

    @staticmethod
    def CheckEK(ek: bytes) -> bool:
        """`CheckEK(ek) -> bool`: encapsulation key check (FIPS 203, §7.2).

        Type check `|ek| = L_ek`, then modulus check: every 12-bit coefficient
        in `ek[0 : L_ek - 32]` must be less than `q`.
        """
        if len(ek) != KEM.L_ek:
            return False
        t = ek[: KEM.L_ek - 32]
        for i in range(0, len(t), 3):
            b0, b1, b2 = t[i], t[i + 1], t[i + 2]
            if (b0 | ((b1 & 0x0F) << 8)) >= KEM.q:
                return False
            if ((b1 >> 4) | (b2 << 4)) >= KEM.q:
                return False
        return True


L_ek = KEM.L_ek
L_c = KEM.L_c


# --- Key generation ---------------------------------------------------------


def expandDecapsulationKey(msk: bytes):
    b = int_(H_blind(msk)) % n
    if b == 0:
        raise HKEFailure("b = 0")
    B = b * G
    (ek, dk) = KEM.KeyGen_internal(H_kem_d(msk), H_kem_z(msk))
    return (b, dk, B, ek)


def KeyGen():
    msk = secrets.token_bytes(32)  # {0,1}^256
    (_, _, B, ek) = expandDecapsulationKey(msk)
    return (msk, (cbytes(B), ek))


# --- Encapsulation ----------------------------------------------------------


def Encaps(B_bytes: bytes, ek: bytes):
    e = 1 + secrets.randbelow(n - 1)
    m = secrets.token_bytes(32)  # {0,1}^256
    return EncapsDerand(B_bytes, ek, e, m)


def EncapsDerand(B_bytes: bytes, ek: bytes, e: int, m: bytes):
    B = lift(B_bytes)
    if B is None:
        raise HKEFailure("lift(B_bytes) failed")
    if not KEM.CheckEK(ek):
        raise HKEFailure("ek fails the FIPS 203 encapsulation key check")
    if not 1 <= e <= n - 1:
        raise HKEFailure("e is not in [1, n-1]")
    if len(m) != 32:
        raise HKEFailure("|m| != 32")
    E = e * G
    E_bytes = cbytes(E)
    K_c = H_ecdh(cbytes(e * B))
    (K_q, c) = KEM.Encaps_internal(ek, m)
    K = H_seed(K_q + K_c + c + E_bytes + ek + B_bytes)
    return (K, (E_bytes, c))


# --- Decapsulation ----------------------------------------------------------


def Decaps(ct, msk: bytes) -> bytes:
    (E_bytes, c) = ct
    (b, dk, B, ek) = expandDecapsulationKey(msk)
    E = lift(E_bytes)
    if E is None:
        raise HKEFailure("lift(E_bytes) failed")
    if len(c) != L_c:
        raise HKEFailure("|c| != L_c")
    K_c = H_ecdh(cbytes(b * E))
    K_q = KEM.Decaps(dk, c)
    K = H_seed(K_q + K_c + c + E_bytes + ek + cbytes(B))
    return K
