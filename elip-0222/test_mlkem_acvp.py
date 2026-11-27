"""ML-KEM-768 backend against NIST's ACVP test vectors for FIPS 203.

Covers every ML-KEM function HKE calls: `KeyGen_internal(d, z)`,
`Encaps_internal(ek, m)`, `Decaps(dk, c)` (including modified ciphertexts,
i.e. implicit rejection) and `CheckEK(ek)`.
"""

import json
from pathlib import Path

import pytest

from hke import KEM

ACVP = Path(__file__).with_name("acvp")
KEYGEN = json.loads((ACVP / "ML-KEM-768-keyGen.json").read_text())
ENCAPDECAP = json.loads((ACVP / "ML-KEM-768-encapDecap.json").read_text())


def x(s: str) -> bytes:
    return bytes.fromhex(s)


def cases(data, function=None):
    tests = [
        t
        for g in data["testGroups"]
        if g["parameterSet"] == "ML-KEM-768" and g.get("function") == function
        for t in g["tests"]
    ]
    assert tests, function
    return pytest.mark.parametrize("t", tests, ids=[f"tc{t['tcId']}" for t in tests])


@cases(KEYGEN)
def test_keygen_internal(t):
    assert KEM.KeyGen_internal(x(t["d"]), x(t["z"])) == (x(t["ek"]), x(t["dk"]))


@cases(ENCAPDECAP, "encapsulation")
def test_encaps_internal(t):
    assert KEM.Encaps_internal(x(t["ek"]), x(t["m"])) == (x(t["k"]), x(t["c"]))


@cases(ENCAPDECAP, "decapsulation")
def test_decaps(t):
    assert KEM.Decaps(x(t["dk"]), x(t["c"])) == x(t["k"])


@cases(ENCAPDECAP, "encapsulationKeyCheck")
def test_check_ek(t):
    assert KEM.CheckEK(x(t["ek"])) == t["testPassed"]
