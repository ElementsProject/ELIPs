"""Unit tests for `hke.py` on fresh random keys.

`test_vectors.py` pins exact outputs; these tests check properties instead:
that a round trip recovers `K`, that every invalid input is rejected, and that
a modified ciphertext gives a wrong `K` rather than an error.
"""

import hashlib

import pytest

from kyber_py.ml_kem import ML_KEM_768 as kyber

import hke
from gen_vectors import flip, invalid_encodings, set_coefficient
from hke import (
    H,
    KEM,
    L_c,
    L_ek,
    HKEFailure,
    Decaps,
    Encaps,
    EncapsDerand,
    G,
    KeyGen,
    cbytes,
    expandDecapsulationKey,
    lift,
    n,
)
from secp256k1lab.secp256k1 import FE  # importable once hke has set up the path

p = FE.SIZE


@pytest.fixture(scope="module")
def recipient():
    """A random recipient: `(msk, B_bytes, ek)`."""
    msk, (B, ek) = KeyGen()
    return msk, B, ek


@pytest.fixture(scope="module")
def encapsulation(recipient):
    """One encapsulation to `recipient`: `(K, (E_bytes, c))`."""
    _, B, ek = recipient
    return Encaps(B, ek)


def resized(data: bytes, length: int) -> bytes:
    """`data` cut or zero-padded to `length` bytes."""
    return data[:length].ljust(length, b"\x00")


# Every kind of byte string that `lift` must reject, used for both B_bytes and E_bytes.
INVALID_POINTS = [pytest.param(bad, id=what) for what, bad in invalid_encodings(cbytes(G))]


# --- secp256k1 and tagged hash ----------------------------------------------


def test_generator_encoding():
    assert cbytes(G).hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    assert cbytes(2 * G).hex() == (
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )


def test_lift_inverts_cbytes():
    for k in (1, 2, 3, 0xDEADBEEF, n - 1):
        P = k * G
        assert lift(cbytes(P)) == P


def test_lift_rejects_noncanonical_x():
    """x = p + 1 would reduce to the valid x = 1, so lift must reject it rather than reduce it."""
    assert lift(b"\x02" + (1).to_bytes(32, "big")) is not None
    assert lift(b"\x02" + (p + 1).to_bytes(32, "big")) is None


def test_lift_rejects_uncompressed_and_hybrid_encodings():
    """lift accepts only the 33-byte compressed form, whatever the 65-byte prefix."""
    uncompressed = G.to_bytes_uncompressed()
    assert len(uncompressed) == 65
    for prefix in (4, 6, 7):
        assert lift(bytes([prefix]) + uncompressed[1:]) is None


@pytest.mark.parametrize(
    "tag",
    [
        "ELIP-HKE/v1/blind",
        "ELIP-HKE/v1/kem-d",
        "ELIP-HKE/v1/kem-z",
        "ELIP-HKE/v1/ecdh",
        "ELIP-HKE/v1/seed/ML-KEM-768",
    ],
)
def test_tagged_hash_matches_bip340_definition(tag):
    msg = bytes(range(100))
    t = hashlib.sha256(tag.encode()).digest()
    assert H(tag, msg) == hashlib.sha256(t + t + msg).digest()


# --- Correctness ------------------------------------------------------------


def test_keygen_is_deterministic_from_msk(recipient):
    msk, B, ek = recipient
    (_, dk1, B1, ek1) = expandDecapsulationKey(msk)
    (_, dk2, B2, ek2) = expandDecapsulationKey(msk)
    assert (B1, ek1, dk1) == (B2, ek2, dk2)
    assert (cbytes(B1), ek1) == (B, ek)


def test_sizes(recipient, encapsulation):
    msk, _, ek = recipient
    K, (E_bytes, c) = encapsulation
    assert len(msk) == 32
    assert len(ek) == L_ek
    assert len(c) == L_c
    assert len(E_bytes) == 33
    assert lift(E_bytes) is not None
    assert len(K) == 32


def test_blinding_scalar_is_reduced_mod_n(monkeypatch):
    """b is H_blind(msk) reduced modulo n. No real msk reaches this: it needs H_blind(msk) >= n."""
    monkeypatch.setattr(hke, "H_blind", lambda msk: (n + 5).to_bytes(32, "big"))
    (b, _, B, _) = expandDecapsulationKey(bytes(32))
    assert b == 5
    assert B == 5 * G


@pytest.mark.parametrize("hash_value", [pytest.param(0, id="0"), pytest.param(n, id="n")])
def test_blinding_scalar_zero_fails(monkeypatch, hash_value):
    """KeyGen fails if b = 0. No real msk reaches this: it needs H_blind(msk) to be 0 or n."""
    monkeypatch.setattr(hke, "H_blind", lambda msk: hash_value.to_bytes(32, "big"))
    with pytest.raises(HKEFailure):
        expandDecapsulationKey(bytes(32))


@pytest.mark.parametrize("draw", [pytest.param(0, id="smallest draw"), pytest.param(n - 2, id="largest draw")])
def test_encaps_is_encaps_derand_with_fresh_randomness(recipient, monkeypatch, draw):
    """Encaps draws e as 1 + randbelow(n - 1), which covers exactly [1, n-1], then 32 bytes of m."""
    _, B, ek = recipient
    requests = []

    def randbelow(bound):
        requests.append(("randbelow", bound))
        return draw

    def token_bytes(length):
        requests.append(("token_bytes", length))
        return bytes(length)

    monkeypatch.setattr(hke.secrets, "randbelow", randbelow)
    monkeypatch.setattr(hke.secrets, "token_bytes", token_bytes)
    assert Encaps(B, ek) == EncapsDerand(B, ek, draw + 1, bytes(32))
    assert requests == [("randbelow", n - 1), ("token_bytes", 32)]


def test_roundtrip(recipient, encapsulation):
    msk, _, _ = recipient
    K, ct = encapsulation
    assert Decaps(ct, msk) == K


@pytest.mark.parametrize("_", range(3))
def test_roundtrip_fresh_keys(_):
    msk, (B, ek) = KeyGen()
    K, ct = Encaps(B, ek)
    assert Decaps(ct, msk) == K


def test_encaps_is_randomized(recipient):
    _, B, ek = recipient
    K1, (E1, c1) = Encaps(B, ek)
    K2, (E2, c2) = Encaps(B, ek)
    assert K1 != K2 and E1 != E2 and c1 != c2


@pytest.mark.parametrize("B_bytes", INVALID_POINTS)
def test_encaps_rejects_invalid_B(recipient, B_bytes):
    _, _, ek = recipient
    with pytest.raises(HKEFailure):
        Encaps(B_bytes, ek)


@pytest.mark.parametrize(
    "e",
    [
        pytest.param(0, id="0"),
        pytest.param(n, id="n"),
        pytest.param(n + 1, id="n + 1"),
        pytest.param(2**256 - 1, id="2^256 - 1"),
    ],
)
def test_encaps_derand_rejects_e_out_of_range(recipient, e):
    """EncapsDerand rejects e outside [1, n-1]; reducing instead would turn e = n + 1 into e = 1."""
    _, B, ek = recipient
    with pytest.raises(HKEFailure):
        EncapsDerand(B, ek, e, bytes(32))


@pytest.mark.parametrize("length", [pytest.param(0, id="empty"), pytest.param(31, id="31"), pytest.param(33, id="33")])
def test_encaps_derand_rejects_wrong_length_m(recipient, length):
    """EncapsDerand rejects an m that is not 32 bytes, rather than failing inside the KEM."""
    _, B, ek = recipient
    with pytest.raises(HKEFailure):
        EncapsDerand(B, ek, 1, bytes(length))


@pytest.mark.parametrize("e", [pytest.param(1, id="1"), pytest.param(n - 1, id="n - 1")])
def test_encaps_derand_accepts_e_at_bounds(recipient, e):
    msk, B, ek = recipient
    K, ct = EncapsDerand(B, ek, e, bytes(32))
    assert Decaps(ct, msk) == K


# --- Encapsulation key check (FIPS 203, 7.2) --------------------------------


def kyber_accepts(ek: bytes) -> bool:
    """Whether kyber-py's own encapsulation accepts `ek`, as an independent check of CheckEK."""
    try:
        kyber.encaps(ek)
        return True
    except ValueError:
        return False


def test_check_ek_accepts_valid_key(recipient):
    _, _, ek = recipient
    assert KEM.CheckEK(ek)


# Both halves of the first 3-byte group, and the first and last coefficient of each polynomial.
@pytest.mark.parametrize("i", [0, 1, 255, 256, 511, 512, 767], ids="coefficient {}".format)
@pytest.mark.parametrize(
    "value",
    [pytest.param(KEM.q - 1, id="q - 1"), pytest.param(KEM.q, id="q"), pytest.param(4095, id="4095")],
)
def test_check_ek_modulus_check(recipient, i, value):
    """CheckEK accepts a coefficient below q and rejects one at or above it, as kyber-py does."""
    _, _, ek = recipient
    modified = set_coefficient(ek, i, value)
    assert KEM.CheckEK(modified) == (value < KEM.q)
    assert KEM.CheckEK(modified) == kyber_accepts(modified)


def test_check_ek_ignores_rho(recipient):
    """The last 32 bytes of ek are the seed rho, not coefficients, so any value is accepted."""
    _, _, ek = recipient
    rho_ff = ek[:-32] + b"\xff" * 32
    assert KEM.CheckEK(rho_ff)
    assert kyber_accepts(rho_ff)


@pytest.mark.parametrize(
    "length",
    [
        pytest.param(0, id="empty"),
        pytest.param(L_ek - 1, id="one byte short"),
        pytest.param(L_ek + 1, id="one byte too long"),
    ],
)
def test_encaps_rejects_wrong_length_ek(recipient, length):
    _, B, ek = recipient
    with pytest.raises(HKEFailure):
        Encaps(B, resized(ek, length))


def test_encaps_rejects_ek_failing_modulus_check(recipient):
    _, B, ek = recipient
    with pytest.raises(HKEFailure):
        Encaps(B, set_coefficient(ek, 5, KEM.q))


# --- Invalid ciphertexts: implicit rejection --------------------------------
# Decaps cannot tell that these ciphertexts were modified: it returns a K
# without error, but not the K that the sender derived.


@pytest.mark.parametrize("i", [0, 1, L_c // 2, L_c - 1], ids="byte {}".format)
def test_tampered_c_gives_wrong_key(recipient, encapsulation, i):
    msk, _, _ = recipient
    K, (E_bytes, c) = encapsulation
    K_bad = Decaps((E_bytes, flip(c, i)), msk)
    assert K_bad != K
    assert len(K_bad) == 32


def test_implicit_rejection_is_deterministic(recipient, encapsulation):
    msk, _, _ = recipient
    _, (E_bytes, c) = encapsulation
    tampered = (E_bytes, flip(c, 7))
    assert Decaps(tampered, msk) == Decaps(tampered, msk)


def test_different_valid_E_gives_wrong_key(recipient, encapsulation):
    msk, _, _ = recipient
    K, (_, c) = encapsulation
    other_E = cbytes(12345 * G)
    assert Decaps((other_E, c), msk) != K


def test_ciphertext_for_other_recipient_gives_wrong_key(encapsulation):
    K, ct = encapsulation
    other_msk, _ = KeyGen()
    assert Decaps(ct, other_msk) != K


def test_ciphertexts_cannot_be_mixed(recipient):
    """E from one encapsulation and c from another give neither encapsulation's K."""
    msk, B, ek = recipient
    K1, (E1, c1) = Encaps(B, ek)
    K2, (E2, c2) = Encaps(B, ek)
    K_mixed = Decaps((E1, c2), msk)
    assert K_mixed not in (K1, K2)


# --- Invalid ciphertexts: explicit failure ----------------------------------
# Decaps fails only on these two format checks.


@pytest.mark.parametrize(
    "length",
    [
        pytest.param(0, id="empty"),
        pytest.param(L_c - 1, id="one byte short"),
        pytest.param(L_c + 1, id="one byte too long"),
    ],
)
def test_wrong_length_c_fails(recipient, encapsulation, length):
    msk, _, _ = recipient
    _, (E_bytes, c) = encapsulation
    with pytest.raises(HKEFailure):
        Decaps((E_bytes, resized(c, length)), msk)


@pytest.mark.parametrize("E_bytes", INVALID_POINTS)
def test_invalid_E_fails(recipient, encapsulation, E_bytes):
    msk, _, _ = recipient
    _, (_, c) = encapsulation
    with pytest.raises(HKEFailure):
        Decaps((E_bytes, c), msk)
