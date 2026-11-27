"""HKE key derivation for Liquid (`elip-hke-confidential-transactions.mediawiki`, "Key derivation").

    msk := HMAC-SHA256(H_mbk(mbk), scriptPubKey)

with `H_mbk` the BIP340 tagged hash with tag `ELIP-HKE/v1/mbk`. The classical
SLIP-77 blinding key of the same scriptPubKey, `HMAC-SHA256(mbk, scriptPubKey)`,
is included for comparison.
"""

import hashlib
import hmac

from hke import H

MBK_TAG = "ELIP-HKE/v1/mbk"


def H_mbk(mbk: bytes) -> bytes:
    return H(MBK_TAG, mbk)


def derive_msk(mbk: bytes, script_pubkey: bytes) -> bytes:
    """HKE secret `msk` for `script_pubkey` under master blinding key `mbk`."""
    assert len(mbk) == 32
    return hmac.new(H_mbk(mbk), script_pubkey, hashlib.sha256).digest()


def slip77_blinding_key(mbk: bytes, script_pubkey: bytes) -> bytes:
    """Classical SLIP-77 blinding private key for `script_pubkey`."""
    assert len(mbk) == 32
    return hmac.new(mbk, script_pubkey, hashlib.sha256).digest()

