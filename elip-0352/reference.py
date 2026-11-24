"""Silent Payments for the Liquid Network — reference implementation. INSECURE, test vectors only.

Up to P_k this is BIP-352 unchanged (secp256k1lab, matching the BIP-352 reference).
The Liquid-specific additions are bk_k (tag LiquidSilentPayments/Blind) and the CT
plumbing below, which needs wallycore instead of secp256k1lab.
"""

from typing import Dict, List, Tuple

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash

import bech32m

TAG_INPUTS = "BIP0352/Inputs"
TAG_SHARED_SECRET = "BIP0352/SharedSecret"
TAG_BLIND = "LiquidSilentPayments/Blind"  # disjoint from TAG_SHARED_SECRET: bk_k and t_k stay independent

SP_ADDRESS_VERSION = 0  # Bech32 character `q`

_HRP = {"liquid": "lqsp", "liquid-testnet": "tlqsp", "liquid-regtest": "tlqsp"}  # distinct from ex/lq, tex/tlq


def ser_uint32(n: int) -> bytes:
    return n.to_bytes(4, "big")


def hrp_for(network: str) -> str:
    return _HRP["liquid"] if network == "liquid" else _HRP["liquid-testnet"]


def encode_silent_payment_address(B_scan: GE, B_spend: GE, network: str = "liquid") -> str:
    """Bech32m(HRP, version || serP(B_scan) || serP(B_spend))."""
    data = bech32m.convertbits(
        B_scan.to_bytes_compressed() + B_spend.to_bytes_compressed(), 8, 5
    )
    return bech32m.bech32_encode(
        hrp_for(network), [SP_ADDRESS_VERSION] + data, bech32m.Encoding.BECH32M
    )


def decode_silent_payment_address(address: str, network: str = "liquid") -> Tuple[GE, GE]:
    version, data = bech32m.decode(hrp_for(network), address)
    if data is None:
        raise ValueError("bad HRP or checksum")
    if version != SP_ADDRESS_VERSION:
        raise ValueError(f"unknown address version {version}")
    if len(data) != 66:
        raise ValueError(f"wrong payload length {len(data)}")
    B_scan = GE.from_bytes_compressed(bytes(data[:33]))
    B_spend = GE.from_bytes_compressed(bytes(data[33:]))
    return B_scan, B_spend


def sum_input_privkeys(input_priv_keys: List[Tuple[Scalar, bool]]) -> Scalar:
    """Sum eligible input keys; negate taproot keys with odd-Y a*G (x-only commitment)."""
    negated = []
    for a, is_taproot in input_priv_keys:
        if is_taproot and not (a * G).has_even_y():
            a = -a
        negated.append(a)
    return Scalar.sum(*negated)


def get_input_hash(outpoints: List[bytes], A: GE) -> Scalar:
    """input_hash = tagged_hash("BIP0352/Inputs", lowest_outpoint || serP(A)); outpoint = txid(32) || vout(4, LE)."""
    lowest = sorted(outpoints)[0]
    h = tagged_hash(TAG_INPUTS, lowest + A.to_bytes_compressed())
    return Scalar.from_bytes_checked(h)


def sender_shared_secret(input_hash: Scalar, a_sum: Scalar, B_scan: GE) -> GE:
    return input_hash * a_sum * B_scan


def receiver_shared_secret(input_hash: Scalar, b_scan: Scalar, A_sum: GE) -> GE:
    return input_hash * b_scan * A_sum


def output_tweak(S: GE, k: int) -> Scalar:
    """t_k = tagged_hash("BIP0352/SharedSecret", serP(S) || ser32(k))."""
    return Scalar.from_bytes_checked(
        tagged_hash(TAG_SHARED_SECRET, S.to_bytes_compressed() + ser_uint32(k))
    )


def output_pubkey(B_spend: GE, S: GE, k: int) -> GE:
    return B_spend + output_tweak(S, k) * G


def output_spend_privkey(b_spend: Scalar, S: GE, k: int) -> Scalar:
    return b_spend + output_tweak(S, k)


# Labels (BIP-352, unchanged): tag a spend key to attribute payments without publishing
# multiple addresses. m=0 is reserved for change and MUST never be handed out.


def label_tweak(b_scan: Scalar, m: int) -> Scalar:
    """hash_{BIP0352/Label}(ser256(b_scan) || ser32(m))."""
    return Scalar.from_bytes_checked(
        tagged_hash("BIP0352/Label", b_scan.to_bytes() + ser_uint32(m))
    )


def labeled_spend_pubkey(B_spend: GE, b_scan: Scalar, m: int) -> GE:
    """B_m = B_spend + label_tweak(b_scan, m)*G, published in place of B_spend."""
    return B_spend + label_tweak(b_scan, m) * G


def labeled_output_spend_privkey(
    b_spend: Scalar, label: Scalar, S: GE, k: int
) -> Scalar:
    """Private key for an output built against a labeled B_m: b_spend + label + t_k."""
    return b_spend + label + output_tweak(S, k)


def blinding_privkey(S: GE, k: int) -> Scalar:
    """bk_k = tagged_hash(TAG_BLIND, serP(S) || ser32(k)); 0/>=n MUST fail (from_bytes_checked raises), per ELIP/BIP-352 t_k."""
    h = tagged_hash(TAG_BLIND, S.to_bytes_compressed() + ser_uint32(k))
    return Scalar.from_bytes_checked(h)


def script_pubkey(P_k: GE) -> bytes:
    """OP_1 <x-only(P_k)> — a P2TR output, no taptweak per BIP-352."""
    return bytes([0x51, 0x20]) + P_k.to_bytes_xonly()


# Tweak server: publishes T = input_hash * A; a client with b_scan computes S = b_scan * T, no private key leaked.


def compute_tweak(input_pubkeys: List[GE], outpoints: List[bytes]) -> Tuple[GE, Scalar, GE]:
    """(T = input_hash * A, input_hash, A) from the eligible input pubkeys."""
    A = GE.sum(*input_pubkeys)
    input_hash = get_input_hash(outpoints, A)
    T = input_hash * A
    return T, input_hash, A


def shared_secret_from_tweak(b_scan: Scalar, T: GE) -> GE:
    return b_scan * T


# Confidential Transactions blinding / unblinding — the only part needing
# Liquid primitives, hence wallycore.


def build_confidential_sp_txout(
    BK_k: GE,
    P_k: GE,
    asset_id: bytes,
    value: int,
    abf: bytes,
    vbf: bytes,
    ephemeral_sk: Scalar,
    input_assets: List[Tuple[bytes, bytes, bytes]],
) -> Dict[str, bytes]:
    """Build a confidential output blinded to BK_k. input_assets is per-input (asset_id, abf, generator)
    for the surjection proof Liquid consensus requires (independent of the SP derivation).
    """
    import os

    import wallycore as wally

    script = script_pubkey(P_k)
    nonce_hash = wally.ecdh_nonce_hash(BK_k.to_bytes_compressed(), ephemeral_sk.to_bytes())
    nonce_pubkey = (ephemeral_sk * G).to_bytes_compressed()

    asset_generator = wally.asset_generator_from_bytes(asset_id, abf)
    value_commitment = wally.asset_value_commitment(value, vbf, asset_generator)
    rangeproof = wally.asset_rangeproof_with_nonce(
        value, nonce_hash, asset_id, abf, vbf,
        value_commitment, script, asset_generator,
        1, 0, 52,
    )

    in_assets = b"".join(a for a, _, _ in input_assets)
    in_abfs = b"".join(f for _, f, _ in input_assets)
    in_gens = b"".join(g for _, _, g in input_assets)
    seed = os.urandom(32)
    surjectionproof = wally.asset_surjectionproof(
        asset_id, abf, asset_generator, seed, in_assets, in_abfs, in_gens,
    )

    return {
        "asset_generator": asset_generator,
        "value_commitment": value_commitment,
        "nonce_pubkey": nonce_pubkey,
        "rangeproof": rangeproof,
        "surjectionproof": bytes(surjectionproof),
        "script_pubkey": script,
    }


def unblind_output(txout: Dict[str, bytes], bk_k: Scalar) -> Dict[str, object]:
    """Unblind with bk_k. Raises if bk_k is wrong (rangeproof fails)."""
    import wallycore as wally

    nonce_hash = wally.ecdh_nonce_hash(txout["nonce_pubkey"], bk_k.to_bytes())
    value, asset, abf, vbf = wally.asset_unblind_with_nonce(
        nonce_hash,
        txout["rangeproof"],
        txout["value_commitment"],
        txout["script_pubkey"],
        txout["asset_generator"],
    )
    return {"asset": bytes(asset), "value": value, "abf": bytes(abf), "vbf": bytes(vbf)}
