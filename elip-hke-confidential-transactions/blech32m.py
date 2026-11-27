"""blech32 / blech32m codec, plus the segwit-style address packing convention
Elements layers on top of it.

Elements' `blech32` is a bech32 variant with a longer, 12-character checksum
(instead of bech32's 6) to preserve reliable error detection at the much
larger payload lengths confidential addresses require. This module
implements the algorithm from its published parameters (charset, generator
polynomial taps, and the blech32/blech32m encoding constants), and is
validated against the exact test vectors in `elements/src/test/blech32_tests.cpp`
(see README.md).

Mirrors the split in the Elements C++ source: `encode`/`decode` here are the
generic codec (equivalent to `blech32::Encode`/`blech32::Decode` — operate on
raw 5-bit quintets, no notion of "witness version"); `encode_segwit`/
`decode_segwit` are the address-specific convention layered on top
(equivalent to the `DestinationEncoder`/`DecodeDestination` logic in
`key_io.cpp`): first quintet is a witness version 0-16, the rest is
`convertbits(payload_bytes, 8, 5)`, and the checksum variant is picked by
witness version (v0 -> blech32, v1+ -> blech32m).
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_GENERATOR = [
    0x7D52FBA40BD886,
    0x5E8DBF1A03950C,
    0x1C3A3C74072A18,
    0x385D72FA0E5139,
    0x7093E5A608865B,
]
_STATE_BITS = 55  # 60-bit total state = 55 + 5, for a 12-symbol (60-bit) checksum
_CHECKSUM_LEN = 12

BLECH32_CONST = 1
BLECH32M_CONST = 0x455972A3350F7A1


def _polymod(values):
    chk = 1
    mask = (1 << _STATE_BITS) - 1
    for v in values:
        top = chk >> _STATE_BITS
        chk = ((chk & mask) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _GENERATOR[i]
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp, data, const):
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0] * _CHECKSUM_LEN) ^ const
    return [(polymod >> (5 * (_CHECKSUM_LEN - 1 - i))) & 31 for i in range(_CHECKSUM_LEN)]


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp: str, data: list, *, m: bool = True) -> str:
    """Generic codec encode: `data` is a list of 5-bit quintets (no checksum)."""
    const = BLECH32M_CONST if m else BLECH32_CONST
    checksum = _create_checksum(hrp, data, const)
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def decode(bech: str):
    """Generic codec decode.

    Returns (encoding, hrp, data) where encoding is `"blech32"`, `"blech32m"`,
    or `None` if the string fails validation for either. `data` is the raw
    list of 5-bit quintets with the checksum stripped (mirrors
    `blech32::Decode` — no witness-version or byte-conversion assumptions).
    """
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + _CHECKSUM_LEN + 1 > len(bech):
        return None, None, None
    hrp = bech[:pos]
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return None, None, None
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    pm = _polymod(_hrp_expand(hrp) + data)
    if pm == BLECH32_CONST:
        encoding = "blech32"
    elif pm == BLECH32M_CONST:
        encoding = "blech32m"
    else:
        return None, None, None
    return encoding, hrp, data[:-_CHECKSUM_LEN]


def encode_segwit(hrp: str, witver: int, payload: bytes) -> str:
    """Address-layer encode: `[witver] || convertbits(payload, 8, 5)`, checksum
    variant selected by witness version (v0 -> blech32, v1+ -> blech32m),
    matching `key_io.cpp`'s `DestinationEncoder`."""
    data = [witver] + convertbits(list(payload), 8, 5, pad=True)
    return encode(hrp, data, m=(witver != 0))


def decode_segwit(bech: str, expected_hrp: str = None):
    """Address-layer decode. Returns (witver, payload_bytes); raises ValueError
    on any validation failure, matching `key_io.cpp`'s `DecodeDestination`
    checks (checksum variant must match witness version; HRP must match)."""
    encoding, hrp, data = decode(bech)
    if encoding is None or not data:
        raise ValueError("invalid blech32/blech32m address (bad checksum or format)")
    if expected_hrp is not None and hrp != expected_hrp.lower():
        raise ValueError(f"unexpected human-readable part {hrp!r} (expected {expected_hrp!r})")
    witver = data[0]
    if witver == 0 and encoding != "blech32":
        raise ValueError("witness v0 address must use blech32 checksum, not blech32m")
    if witver != 0 and encoding != "blech32m":
        raise ValueError("witness v1+ address must use blech32m checksum, not blech32")
    if witver > 16:
        raise ValueError(f"invalid witness version {witver}")
    payload = convertbits(data[1:], 5, 8, pad=False)
    if payload is None:
        raise ValueError("witness payload is not a valid byte-aligned 5-to-8 bit conversion")
    return witver, bytes(payload)
