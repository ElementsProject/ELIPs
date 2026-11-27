# ELIP Hybrid Key Exchange for Confidential Transactions: Liquid integration demo

Reference code for `../elip-hke-confidential-transactions.mediawiki`: key derivation, HKE confidential addresses, nonce and placeholder encoding, and sender/recipient seed agreement.
The demo imports the HKE reference implementation in `hke.py` of ELIP 222 (https://github.com/ElementsProject/ELIPs/pull/46).

## Run

```sh
cd elip-hke-confidential-transactions
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py
.venv/bin/python -m pytest -v
.venv/bin/python gen_vectors.py  # regenerate vectors.json (deterministic)
```

The demo derives classical and HKE confidential addresses for one scriptPubKey from a random master blinding key, and renders both as QR codes (`classical_address_qr.png` and `address_qr.png`).
It passes the recipient's HKE public key through a placeholder to the blinder, encodes the resulting ciphertext as an HKE nonce, and checks that the recipient recovers the sender's seed `K`.

## Modules

- `blech32m.py` and `classical_address.py` — the existing confidential segwit address format, used for comparison; the HKE address format reuses only the alphabet and bit regrouping.
- `address.py` — HKE confidential addresses under the proposed `el2` regtest HRP, with CRC-32, canonical base32 padding and checks on witness programs and public keys.
- `key_derivation.py` — `msk := HMAC-SHA256(H_mbk(mbk), scriptPubKey)` from the ELIP's Key derivation, plus the SLIP-77 blinding key for comparison.
- `nonce.py` — nonce parsing, HKE ciphertext and placeholder encoding, output nonce checks, Simplicity's nonce hash input and recipient seed recovery.
- `gen_vectors.py` / `vectors.json` — deterministic P2WPKH, P2WSH and P2TR vectors from `(mbk, scriptPubKey, e, m)` to keys, addresses, ciphertexts, seeds and nonce encodings.
- `test_vectors.py` / `test_nonce.py` — vector reproduction, field boundaries, prefix conversion, activation and explicit-value restrictions, malformed-output recovery and address decoding.
  The CRC test documents an undetected 30-bit burst across the payload/checksum boundary; this encoding does not have the usual CRC burst guarantee.
- `demo.py` — address, blinding and seed-recovery flow.

## Scope

This code does not implement Elements transaction validation, range-proof creation or rewind, PSET, or Simplicity jets.
The Simplicity vectors cover only the nonce's contribution to hashing, not complete transaction hashes or jet commitments.
HRPs still need confirmation by Elements maintainers, and the demo uses a random witness program rather than a spendable destination.
