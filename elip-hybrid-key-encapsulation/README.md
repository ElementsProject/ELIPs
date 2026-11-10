# ELIP HKE reference implementation

Python reference implementation of the Specification section of `../elip-hybrid-key-encapsulation.mediawiki`.
It is for checking the spec, not for production: neither secp256k1lab nor `kyber-py` is constant time.
Requires Python 3.11 or later (secp256k1lab's minimum).

## Run

```sh
cd elip-hybrid-key-encapsulation
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -v
```

## Files

- `hke.py` — the spec, function by function.
- `secp256k1lab/` — vendored copy of secp256k1lab (see below); not modified.
- `pyproject.toml` — packages `hke` so that other code can depend on it with `pip install -e`.
- `test_hke.py` — correctness and invalid-ciphertext tests.
- `gen_vectors.py` — writes `vectors.json` from fixed, label-derived inputs.
- `vectors.json` — the test vectors.
- `test_vectors.py` — checks the implementation against `vectors.json`, and that the file matches what `gen_vectors.py` produces.
- `fetch_acvp.py` — downloads NIST's ACVP ML-KEM-768 test vectors into `acvp/`, pinned to an ACVP-Server commit.
- `test_mlkem_acvp.py` — checks the ML-KEM-768 backend against `acvp/`.

## Primitives

The reference implements only the HKE layer itself; both primitives come from canonical, pinned sources.

- **secp256k1:** a vendored copy of [secp256k1lab](https://github.com/secp256k1lab/secp256k1lab) at version 1.0.0 (commit [`44dc4bd893b8f03e621585e3bf255253e0e0fbfb`](https://github.com/secp256k1lab/secp256k1lab/commit/44dc4bd893b8f03e621585e3bf255253e0e0fbfb)), imported the same way as in the BIP-352 and BIP-374 reference implementations.
  The vendored source files are byte-identical to the copy in `bitcoin/bips/bip-0352/secp256k1lab` (same git blob hashes).
  `k*P` is `GE.__rmul__`, `cbytes` is `GE.to_bytes_compressed`, `lift` is `GE.from_bytes_compressed` behind explicit length, prefix and `X < p` checks (the library asserts rather than raises on length), and `H_t` is `util.tagged_hash`.
- **ML-KEM-768:** [`kyber-py`](https://github.com/GiacomoPope/kyber-py) 1.2.0 (pinned in `requirements.txt`), a direct transcription of FIPS 203.
  No BIP ships ML-KEM, so there is no BIP convention to follow here.
  It passes every ML-KEM-768 case in NIST's ACVP vectors for the functions HKE uses: 25 `keyGen` (`KeyGen_internal(d, z)`), 25 `encapsulation` (`Encaps_internal(ek, m)`), 10 `decapsulation` (5 with a modified ciphertext, i.e. implicit rejection) and 10 `encapsulationKeyCheck` (`CheckEK`).
  The ACVP vectors are the conformance test for FIPS 203, so any implementation that passes them computes the same function on these inputs.

## Correspondence with the pseudocode

| Spec | `hke.py` |
|---|---|
| `cbytes`, `int`, `lift` | `cbytes`, `int_`, `lift` (returns `None` on failure) |
| `H_t`, `H_blind`, `H_kem-d`, `H_kem-z`, `H_ecdh`, `H_seed` | `H`, `H_blind`, `H_kem_d`, `H_kem_z`, `H_ecdh`, `H_seed` |
| `KEM.KeyGen_internal`, `KEM.Encaps_internal`, `KEM.Decaps`, `L_ek`, `L_c` | `KEM.*`, backed by `kyber-py` |
| `KEM.CheckEK` | `KEM.CheckEK`, implemented directly from FIPS 203 §7.2 and checked against NIST ACVP |
| `expandDecapsulationKey`, `KeyGen`, `Encaps`, `EncapsDerand`, `Decaps` | same names, same step order |
| "fail" | `raise HKEFailure` |

## Tests

- **Correctness:** round trip `Decaps(Encaps(B_bytes, ek)) = K`, deterministic `expandDecapsulationKey`, object sizes, randomized `Encaps`.
- **Invalid public key:** every class of invalid `B_bytes` (empty, `O`, bad prefix, uncompressed, hybrid, wrong length, `X >= p`, `X` not on the curve) makes `Encaps` raise `HKEFailure`.
- **Primitive wiring:** generator encodings, `lift`/`cbytes` round trip, `lift` rejecting 65-byte uncompressed and hybrid encodings and a non-canonical `X = p + 1` (which reduces to a valid x coordinate), and the tagged hash equal to the BIP340 formula for every tag.
- **Encapsulation key check:** `Encaps` rejects an `ek` of the wrong length or with a coefficient `>= q`; `CheckEK` agrees with `kyber-py` on boundary values at the first and last coefficient of each polynomial, and ignores the last 32 bytes (`rho`).
- **Ephemeral scalar:** `EncapsDerand` rejects `e` outside `[1, n-1]` (`0`, `n`, `n + 1`, `2^256 - 1`) and accepts both bounds; it also rejects an `m` that is not 32 bytes.
- **Randomness:** with `secrets` replaced, `Encaps` equals `EncapsDerand` with `e = 1 + randbelow(n - 1)` and a 32-byte `m`, at the smallest and largest draw; `KeyGen` returns a 32-byte `msk`.
- **Unreachable branches:** with `H_blind` replaced, `expandDecapsulationKey` reduces `H_blind(msk)` modulo `n` and fails on `b = 0`; no real `msk` reaches either, so no vector covers them.
- **Invalid ciphertext, implicit rejection:** a tampered `c`, a different valid `E`, a ciphertext for another recipient, or `E` and `c` taken from different encapsulations all decapsulate without error to a wrong `K`; rejection is deterministic.
- **Invalid ciphertext, explicit failure:** wrong `|c|` and every class of invalid `E_bytes` (empty, `O`, bad prefix, uncompressed, hybrid, wrong length, `X >= p`, `X` not on the curve) raise `HKEFailure`.

## Test vectors

`vectors.json` has five groups; byte strings and scalars are lowercase hex, scalars 32-byte big-endian.
Each vector has a `comment`, its inputs under `given`, and the values an implementation must compute under `expected`.
The two `*_failure` groups have no `expected`: the call must fail.

| Group | `given` | `expected` |
|---|---|---|
| `valid` | `msk`, `e`, `m` | `b`, `B`, `ek`, `dk`, `E_bytes`, `c`, `K_c`, `K_q`, `K` |
| `encaps_valid` | `B`, `ek`, `e`, `m` | `E_bytes`, `c`, `K_c`, `K_q`, `K`, for an `ek` that `KeyGen` does not produce |
| `implicit_rejection` | `msk`, `E_bytes`, `c` | the `K_c`, `K_q` and `K` that `Decaps` computes |
| `decaps_failure` | `msk`, `E_bytes`, `c` | none; `Decaps` fails |
| `encaps_failure` | `B`, `ek`, `e`, `m` | none; `EncapsDerand` fails |

Regenerate with `.venv/bin/python gen_vectors.py`; output is deterministic.
New `valid`, `encaps_valid` and `implicit_rejection` vectors are appended, so earlier ones keep their index.

Each vector targets a mistake that an implementation could make, and each failure vector has exactly one invalid input.
Beyond the generic cases, the vectors contain:

- `e = 1` and `e = n - 1`, the ends of the range that `Encaps` draws from, and an all-zero `m`;
- x coordinates of `B`, `E` and `e*B` that start with a zero byte, which catch an x encoded in fewer than 32 bytes, and a `K_c` and a `K_q` that start with a zero byte, which catch an implementation that does not handle them as fixed 32-byte strings;
- an `ek` with coefficients `q - 1`, the largest valid value, and failing `ek`s with a coefficient `>= q` at both ends of each polynomial, or with the size of a valid ML-KEM-512 or ML-KEM-1024 key;
- for both `E_bytes` and `B_bytes`, encodings that other decoders accept: SEC1's `0x00` for `O`, uncompressed and hybrid encodings (all three accepted by OpenSSL, the last two by `secp256k1_ec_pubkey_parse`), the x-only encoding, 33 zero bytes, a wrong prefix, `X >= p` that is valid mod `p`, `X` off the curve, and wrong lengths;
- `e = 0`, `e = n` and values of `e` above `n`, and an `m` one byte short or too long;
- each way to get a wrong `K` without a failure: a modified `c`, which the KEM rejects implicitly, a different `E` with an unmodified `c`, and a ciphertext for another recipient.

No HKE vector reaches ML-KEM's rarely taken branches, such as SampleNTT reading more than 575 bytes of XOF output (probability 2^-38 per seed), since the KEM seeds are hashes of `msk`; an ML-KEM backend should also pass NIST's ACVP vectors, as `kyber-py` does in `test_mlkem_acvp.py`, and the C2SP CCTV and Wycheproof ML-KEM vectors.

During development, the secp256k1 side of the vectors was cross-checked once against a hand-written pure-Python implementation and libsecp256k1, in addition to secp256k1lab.
`K_q` and the implicit-rejection keys were additionally cross-checked once against PQClean's ML-KEM-768 (via `pqcrypto`).
