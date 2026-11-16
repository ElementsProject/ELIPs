"""Check `hke.py` against `vectors.json`, one test per vector.

Each test calls the function the vector's group is about on the vector's
`given` values, and compares the result with its `expected` values, or, for
the `*_failure` groups, expects `HKEFailure` from the vector's one invalid input.
"""

import json

import pytest

from gen_vectors import VECTORS, generate
from hke import (
    KEM,
    L_c,
    H_ecdh,
    HKEFailure,
    Decaps,
    EncapsDerand,
    cbytes,
    expandDecapsulationKey,
    lift,
    n,
)

V = json.loads(VECTORS.read_text())

SCALARS = {"e", "b"}


def decode(fields: dict) -> dict:
    """Turn a vector's hex strings into bytes, and the scalars `e` and `b` into integers."""
    return {k: int(v, 16) if k in SCALARS else bytes.fromhex(v) for k, v in fields.items()}


def vectors(group: str):
    """The vectors of `group`, named after their comments in the test report."""
    return pytest.mark.parametrize("v", V[group], ids=[v["comment"] for v in V[group]])


def test_vectors_file_is_current():
    """`vectors.json` is exactly what `gen_vectors.py` produces."""
    assert generate() == V


@vectors("valid")
def test_valid(v):
    """Key generation, encapsulation and decapsulation reproduce every expected value."""
    given, expected = decode(v["given"]), decode(v["expected"])

    # The recipient derives its keys from msk.
    (b, dk, B, ek) = expandDecapsulationKey(given["msk"])
    assert b == expected["b"]
    assert cbytes(B) == expected["B"]
    assert ek == expected["ek"]
    assert dk == expected["dk"]

    # The sender encapsulates to the recipient's public key (B, ek).
    K, (E_bytes, c) = EncapsDerand(expected["B"], expected["ek"], given["e"], given["m"])
    assert E_bytes == expected["E_bytes"]
    assert c == expected["c"]
    assert K == expected["K"]

    # The two shared secrets that K combines.
    assert H_ecdh(cbytes(b * lift(E_bytes))) == expected["K_c"]
    assert KEM.Decaps(dk, c) == expected["K_q"]

    # The recipient decapsulates the same K.
    assert Decaps((E_bytes, c), given["msk"]) == expected["K"]


@vectors("encaps_valid")
def test_encaps_valid(v):
    """Encapsulation accepts an ek that KeyGen does not produce and gives the expected values."""
    given, expected = decode(v["given"]), decode(v["expected"])
    assert KEM.CheckEK(given["ek"])

    K, (E_bytes, c) = EncapsDerand(given["B"], given["ek"], given["e"], given["m"])
    assert E_bytes == expected["E_bytes"]
    assert c == expected["c"]
    assert K == expected["K"]

    # The two shared secrets that K combines.
    assert H_ecdh(cbytes(given["e"] * lift(given["B"]))) == expected["K_c"]
    assert KEM.Encaps_internal(given["ek"], given["m"])[0] == expected["K_q"]


@vectors("implicit_rejection")
def test_implicit_rejection(v):
    """Decapsulation of a modified ciphertext does not fail, and gives the expected wrong K."""
    given, expected = decode(v["given"]), decode(v["expected"])

    # The two shared secrets that K combines.
    (b, dk, _, _) = expandDecapsulationKey(given["msk"])
    assert H_ecdh(cbytes(b * lift(given["E_bytes"]))) == expected["K_c"]
    assert KEM.Decaps(dk, given["c"]) == expected["K_q"]

    assert Decaps((given["E_bytes"], given["c"]), given["msk"]) == expected["K"]


def only_invalid(checks: dict) -> str:
    """The name of the one input that fails its check, so that the vector tests that check."""
    invalid = [name for name, valid in checks.items() if not valid]
    assert len(invalid) == 1, invalid
    return invalid[0]


@vectors("decaps_failure")
def test_decaps_failure(v):
    """Decapsulation fails on an invalid E_bytes or a c of the wrong length."""
    assert "expected" not in v
    given = decode(v["given"])
    invalid = only_invalid({"E_bytes": lift(given["E_bytes"]) is not None, "c": len(given["c"]) == L_c})
    with pytest.raises(HKEFailure, match={"E_bytes": "E_bytes", "c": r"\|c\|"}[invalid]):
        Decaps((given["E_bytes"], given["c"]), given["msk"])


@vectors("encaps_failure")
def test_encaps_failure(v):
    """Encapsulation fails on an invalid B, an ek that fails CheckEK, an e outside [1, n-1], or a wrong |m|."""
    assert "expected" not in v
    given = decode(v["given"])
    invalid = only_invalid(
        {
            "B": lift(given["B"]) is not None,
            "ek": KEM.CheckEK(given["ek"]),
            "e": 1 <= given["e"] <= n - 1,
            "m": len(given["m"]) == 32,
        }
    )
    match = {"B": "B_bytes", "ek": "encapsulation key", "e": "e is not", "m": r"\|m\|"}[invalid]
    with pytest.raises(HKEFailure, match=match):
        EncapsDerand(given["B"], given["ek"], given["e"], given["m"])
