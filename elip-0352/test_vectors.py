"""Reference test vectors, in the style of the BIP-352 reference tests."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secp256k1lab.secp256k1 import G, GE, Scalar  # noqa: E402

from reference import (  # noqa: E402
    blinding_privkey,
    compute_tweak,
    decode_silent_payment_address,
    encode_silent_payment_address,
    get_input_hash,
    label_tweak,
    labeled_output_spend_privkey,
    labeled_spend_pubkey,
    output_pubkey,
    output_spend_privkey,
    receiver_shared_secret,
    script_pubkey,
    sender_shared_secret,
    shared_secret_from_tweak,
    sum_input_privkeys,
)


def sk(b: int) -> Scalar:
    return Scalar.from_bytes_checked(bytes([b] * 32))


def outpoint(txid_byte: int, vout: int) -> bytes:
    return bytes([txid_byte] * 32) + vout.to_bytes(4, "little")


def test_vectors():
    """b_scan = 0x11*32, b_spend = 0x22*32; inputs 0x31 @ 0x10:0, 0x32 @ 0x20:1."""
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    input_priv_keys = [(sk(0x31), False), (sk(0x32), False)]
    outpoints = [outpoint(0x10, 0), outpoint(0x20, 1)]

    a_sum = sum_input_privkeys(input_priv_keys)
    A = a_sum * G
    input_hash = get_input_hash(outpoints, A)

    assert (
        A.to_bytes_compressed().hex()
        == "031195a8046dcbb8e17034bca630065e7a0982e4e36f6f7e5a8d4554e4846fcd99"
    ), "A"
    assert (
        input_hash.to_bytes().hex()
        == "d392922c00280a7e8d282182f5026f2fddbc74c1e1de18b4822128b2b77ec641"
    ), "input_hash"

    expected = [
        (
            0,
            "02a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
            "0344e1289497e6da66fde710d2f38de053fc07355e405524401d7d609df5a1a8cc",
            "70ab8897b64bd21b427339ff4d014b883191ef6425862246c53bfc27a59aa3f0",
            "f03c436d2cd67ae1fecf7d88a38aa3a03c0abea43feaf6da8eb71e2e3a866bda",
            "5120a29d9716417c964ca9e477343e71ffe730a4991a3eaad668eabec84e9feb7931",
        ),
        (
            1,
            "0229d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
            "03efdeda770ccdbe8bf466fba48bfd2b2c436ab0c04658fc6d6c277de5078129fa",
            "945ba73a9804f62089c7d2ffdc079031031f0aebab372cec17ef9c110ebceb10",
            "9eff3472230fc83ef5ea8f8c80401c4eecd595a048bd2482a107d3a49baa5a58",
            "512029d77654023af267dbe9cb7ff1956f947c816f203494381308387168fb010c92",
        ),
    ]

    S_send = sender_shared_secret(input_hash, a_sum, B_scan)
    S_recv = receiver_shared_secret(input_hash, b_scan, A)
    assert S_send == S_recv, "sender and receiver shared secrets agree"

    for k, pk, bk_pub, bk_sk, spk_sk, script in expected:
        P_k = output_pubkey(B_spend, S_send, k)
        bk = blinding_privkey(S_send, k)
        BK_k = bk * G
        spend_sk = output_spend_privkey(b_spend, S_send, k)

        # The receiver recomputes the same P_k from b_spend and the shared secret.
        assert output_pubkey(B_spend, S_recv, k) == P_k, f"P_k receiver agrees k={k}"
        assert spend_sk * G == P_k, f"spend_sk * G == P_k k={k}"

        assert P_k.to_bytes_compressed().hex() == pk, f"P_k k={k}"
        assert BK_k.to_bytes_compressed().hex() == bk_pub, f"BK_k k={k}"
        assert bk.to_bytes().hex() == bk_sk, f"bk_k k={k}"
        assert spend_sk.to_bytes().hex() == spk_sk, f"spend_sk k={k}"
        assert script_pubkey(P_k).hex() == script, f"scriptPubKey k={k}"

    assert (
        encode_silent_payment_address(B_scan, B_spend, "liquid")
        == "lqsp1qqd8n2k7uklxq4aegau7vawtptkgxsja4kt99lpv6krctwpq8tpc65qjxd4lu4etruh9sngx3su9mtqp5fqzxz7re59y5nnez9p03ht3lyudcfhfe"
    ), "mainnet address"


def test_taproot_even_y_negation():
    """BIP-352 even-Y normalization for taproot inputs."""
    odd = None
    for b in range(1, 0x100):
        if not (sk(b) * G).has_even_y():
            odd = sk(b)
            break
    assert odd is not None

    a_tr = sum_input_privkeys([(odd, True)])
    a_legacy = sum_input_privkeys([(odd, False)])
    assert a_tr != a_legacy, "odd-Y taproot key is negated"
    assert a_tr == -a_legacy, "negation is exactly n - a"

    A_tr = a_tr * G
    assert A_tr.to_bytes_xonly() == (odd * G).to_bytes_xonly(), "x-only A unchanged"

    even = None
    for b in range(1, 0x100):
        if (sk(b) * G).has_even_y():
            even = sk(b)
            break
    assert even is not None
    assert sum_input_privkeys([(even, True)]) == sum_input_privkeys([(even, False)])


def test_tweak_server_agreement():
    """A tweak server publishes T = input_hash * A; client computes S = b_scan * T."""
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    input_priv_keys = [(sk(0x55), False)]
    op = outpoint(0xAA, 0)

    a_sum = sum_input_privkeys(input_priv_keys)
    A = a_sum * G
    input_hash = get_input_hash([op], A)

    S_sender = sender_shared_secret(input_hash, a_sum, B_scan)

    T, ih_server, A_server = compute_tweak([sk(0x55) * G], [op])
    assert A_server == A and ih_server == input_hash
    S_client = shared_secret_from_tweak(b_scan, T)

    assert S_client == S_sender, "client shared secret matches sender"
    assert output_pubkey(B_spend, S_client, 0) == output_pubkey(B_spend, S_sender, 0)


def test_address_round_trip_and_network_separation():
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    for network in ("liquid", "liquid-testnet"):
        enc = encode_silent_payment_address(B_scan, B_spend, network)
        d_scan, d_spend = decode_silent_payment_address(enc, network)
        assert d_scan == B_scan and d_spend == B_spend

    mainnet = encode_silent_payment_address(B_scan, B_spend, "liquid")
    with pytest.raises(ValueError):
        decode_silent_payment_address(mainnet, "liquid-testnet")


def test_ct_round_trip_unblind_with_bk():
    """CT round-trip: sender blinds to BK_k, receiver unblinds with bk_k."""
    pytest.importorskip("wallycore")
    from reference import build_confidential_sp_txout, unblind_output

    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    input_priv_keys = [(sk(0x33), False)]
    op = outpoint(0xAB, 0)
    a_sum = sum_input_privkeys(input_priv_keys)
    A = a_sum * G
    input_hash = get_input_hash([op], A)

    k = 0
    S = sender_shared_secret(input_hash, a_sum, B_scan)
    P_k = output_pubkey(B_spend, S, k)
    bk = blinding_privkey(S, k)
    BK_k = bk * G

    asset_id = bytes([0x42] * 32)
    value = 123_456
    abf = bytes([0x01] * 32)
    vbf = bytes([0x02] * 32)
    ephemeral_sk = sk(0x07)

    import wallycore as wally

    input_abf = bytes([0x03] * 32)
    input_gen = wally.asset_generator_from_bytes(asset_id, input_abf)
    input_assets = [(asset_id, input_abf, input_gen)]

    txout = build_confidential_sp_txout(
        BK_k, P_k, asset_id, value, abf, vbf, ephemeral_sk, input_assets
    )
    assert len(txout["surjectionproof"]) > 0

    S_recv = receiver_shared_secret(input_hash, b_scan, A)
    bk_recv = blinding_privkey(S_recv, k)
    assert bk_recv == bk

    recovered = unblind_output(txout, bk_recv)
    assert recovered["value"] == value
    assert recovered["abf"] == abf
    assert recovered["vbf"] == vbf

    wrong_bk = blinding_privkey(
        receiver_shared_secret(input_hash, sk(0x99), A), k
    )
    assert wrong_bk != bk
    with pytest.raises(Exception):
        unblind_output(txout, wrong_bk)


def test_labels():
    # BIP-352 labels, unchanged on Liquid: B_m = B_spend + label_tweak(b_scan, m)*G.
    # m=0 is reserved for change. We verify the sender/receiver key-derivation
    # agreement for a labeled address: sender uses the published B_m in place
    # of B_spend, receiver reconstructs the same spend key offline.
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    input_priv_keys = [(sk(0x44), False)]
    op = outpoint(0xcd, 0)
    a_sum = sum_input_privkeys(input_priv_keys)
    A = a_sum * G
    input_hash = get_input_hash([op], A)

    S_send = sender_shared_secret(input_hash, a_sum, B_scan)
    S_recv = receiver_shared_secret(input_hash, b_scan, A)
    assert S_send == S_recv

    for m in (1, 2, 7):
        label = label_tweak(b_scan, m)
        B_m = labeled_spend_pubkey(B_spend, b_scan, m)
        assert B_m == B_spend + label * G

        P_k = output_pubkey(B_m, S_send, 0)
        spend_sk = labeled_output_spend_privkey(b_spend, label, S_recv, 0)
        assert spend_sk * G == P_k, f"labeled spend key matches P_k, m={m}"

    assert label_tweak(b_scan, 0) != label_tweak(b_scan, 1)


def test_pegin_input_excluded_from_shared_secret():
    # A peg-in input contributes no pubkey to the shared secret (per the
    # ELIP's 'Input eligibility for peg-ins and issuances' bullet), but its
    # outpoint still participates in outpoint_L since that's read from the
    # Liquid transaction itself, not the Bitcoin-chain prevout it spends.
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan = b_scan * G

    eligible_priv_keys = [(sk(0x51), False), (sk(0x52), False)]
    pegin_outpoint = outpoint(0xfe, 0)  # peg-in's own outpoint on Liquid
    eligible_outpoints = [outpoint(0x61, 0), outpoint(0x62, 1)]
    all_outpoints = eligible_outpoints + [pegin_outpoint]

    a_sum = sum_input_privkeys(eligible_priv_keys)
    A = a_sum * G

    input_hash_with_pegin = get_input_hash(all_outpoints, A)
    input_hash_without_pegin = get_input_hash(eligible_outpoints, A)

    lowest_with = sorted(all_outpoints)[0]
    if lowest_with == pegin_outpoint:
        assert input_hash_with_pegin != input_hash_without_pegin
    else:
        assert input_hash_with_pegin == input_hash_without_pegin

    S = sender_shared_secret(input_hash_with_pegin, a_sum, B_scan)
    S_from_eligible_only = sender_shared_secret(
        input_hash_with_pegin, sum_input_privkeys(eligible_priv_keys), B_scan
    )
    assert S == S_from_eligible_only


def test_testnet_and_regtest_addresses():
    # tlqsp is shared by testnet and regtest per the ELIP (mirrors BIP-352's
    # single non-mainnet HRP, which itself only names signet/testnet but is
    # conventionally extended to regtest by implementations).
    b_scan, b_spend = sk(0x11), sk(0x22)
    B_scan, B_spend = b_scan * G, b_spend * G

    testnet_addr = encode_silent_payment_address(B_scan, B_spend, "liquid-testnet")
    regtest_addr = encode_silent_payment_address(B_scan, B_spend, "liquid-regtest")
    assert testnet_addr == regtest_addr, "testnet and regtest share tlqsp"
    assert testnet_addr.startswith("tlqsp1")

    for network in ("liquid-testnet", "liquid-regtest"):
        d_scan, d_spend = decode_silent_payment_address(testnet_addr, network)
        assert d_scan == B_scan and d_spend == B_spend

    mainnet_addr = encode_silent_payment_address(B_scan, B_spend, "liquid")
    assert mainnet_addr != testnet_addr
    assert mainnet_addr.startswith("lqsp1")
