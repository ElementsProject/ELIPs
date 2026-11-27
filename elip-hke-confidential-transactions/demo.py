"""Liquid integration demo: recipient generates an HKE confidential
address, sender encapsulates to it, recipient recovers the same seed, and the
address round-trips through its string encoding and a QR code.

The HKE itself is the reference implementation in `../elip-0222/hke.py`
(`elip-0222.mediawiki`); this demo adds the Liquid-side address and nonce encodings
(`elip-hke-confidential-transactions.mediawiki`).

Run with: python demo.py
"""

import os
from pathlib import Path

import hke
from address import HKE_VERSION, HRP, HKEConfidentialAddress, decode_address, render_qr, witness_script_pubkey
from classical_address import ClassicalConfidentialAddress, HRP_REGTEST, decode_classical_address
from key_derivation import derive_msk, slip77_blinding_key
from nonce import decode_placeholder, encode_hke_nonce, encode_placeholder, recover_hke_seed

HERE = Path(__file__).parent


def main():
    print(f"=== HKE Liquid demo — HRP={HRP!r}, hke_version=0x{HKE_VERSION:02x} ===\n")

    # --- Recipient setup (elip-hke-confidential-transactions.mediawiki Key derivation) ---
    mbk = os.urandom(32)  # master blinding key
    program = os.urandom(20)  # placeholder witness program (e.g. a P2WPKH-sized program)
    script_pubkey = witness_script_pubkey(0, program)
    msk = derive_msk(mbk, script_pubkey)
    (_, _, B, ek) = hke.expandDecapsulationKey(msk)
    B_bytes = hke.cbytes(B)

    # Today's Liquid confidential address for the same scriptPubKey (blech32,
    # real "el" regtest HRP), with its SLIP-77 blinding key. Both addresses
    # derive from the same mbk; their blinding keys differ.
    B_slip77 = hke.cbytes(hke.int_(slip77_blinding_key(mbk, script_pubkey)) * hke.G)
    classical_obj = ClassicalConfidentialAddress(B=B_slip77, program=program)
    classical_str = classical_obj.encode(HRP_REGTEST)
    print(f"Classical (today's) confidential address ({len(classical_str)} chars):\n{classical_str}")
    decoded_classical = decode_classical_address(classical_str, HRP_REGTEST)
    assert decoded_classical.B == classical_obj.B and decoded_classical.program == classical_obj.program
    print("Classical address round-trip decode: OK\n")
    render_qr(classical_str, HERE / "classical_address_qr.png")

    addr_obj = HKEConfidentialAddress(B=B_bytes, ek=ek, witver=0, program=program)
    addr_str = addr_obj.encode()
    print(f"HKE confidential address ({len(addr_str)} chars, same scriptPubKey as above):\n{addr_str}\n")

    qr_path = HERE / "address_qr.png"
    qr_version = render_qr(addr_str, qr_path)
    modules = qr_version * 4 + 17
    print(f"QR code written to {qr_path} (QR version {qr_version}, {modules}x{modules} modules)")
    print()

    decoded = decode_address(addr_str)
    assert decoded.B == addr_obj.B
    assert decoded.ek == addr_obj.ek
    assert decoded.script_pubkey() == script_pubkey
    print("Address round-trip decode (string -> B, ek, witver, program): OK\n")

    # --- Constructor passes the recipient keys to the blinder ---
    placeholder = encode_placeholder(decoded.B, decoded.ek)
    B_bytes, ek = decode_placeholder(placeholder)
    K_sender, (E_bytes, c) = hke.Encaps(B_bytes, ek)
    nonce = encode_hke_nonce(E_bytes, c)
    print(f"Nonce: {len(placeholder)}-byte placeholder -> {len(nonce)}-byte HKE ciphertext")
    print(f"Sender:    E = {E_bytes.hex()}")
    print(f"           c = {len(c)} bytes, ciphertext = {c.hex()[:32]}...")
    print(f"           K_sender    = {K_sender.hex()}")

    # --- Recipient recovery (elip-0222.mediawiki Decaps) ---
    K_recipient = recover_hke_seed(nonce, msk)
    assert K_recipient is not None, "unrecoverable nonce"
    print(f"Recipient: K_recipient = {K_recipient.hex()}\n")

    assert K_sender == K_recipient, "seed mismatch between sender and recipient!"
    print("Seed agreement (K_sender == K_recipient): OK")


if __name__ == "__main__":
    main()
