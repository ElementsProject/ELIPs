"""Reference nNonce encoding for elip-hke-confidential-transactions.mediawiki, including unblinded placeholders.

Parsing checks structure only. Point validity belongs to HKE, not consensus.
The output checks below illustrate the ELIP; they do not validate transactions.
"""

from hashlib import sha256
from io import BytesIO
from typing import BinaryIO

import hke

NONCE_LENGTHS = {0: 1, 1: 33, 2: 33, 3: 33, 4: 1121, 5: 1121, 6: 1217, 7: 1217}


def read_nonce(stream: BinaryIO) -> bytes:
    """Read one nonce, leaving the next transaction field untouched."""
    prefix = stream.read(1)
    if not prefix or prefix[0] not in NONCE_LENGTHS:
        raise ValueError("missing or unknown nonce prefix")
    length = NONCE_LENGTHS[prefix[0]]
    payload = stream.read(length - 1)
    if len(payload) != length - 1:
        raise ValueError("truncated nonce")
    return prefix + payload


def parse_nonce(raw: bytes) -> bytes:
    """Parse an isolated nonce field, rejecting trailing data."""
    stream = BytesIO(raw)
    nonce = read_nonce(stream)
    if stream.read(1):
        raise ValueError("trailing nonce data")
    return nonce


def _encode(point_bytes: bytes, data: bytes, offset: int, data_length: int) -> bytes:
    if len(point_bytes) != 33 or point_bytes[0] not in (2, 3):
        raise ValueError("expected a 33-byte compressed point encoding")
    if len(data) != data_length:
        raise ValueError("wrong KEM field length")
    return bytes([point_bytes[0] + offset]) + point_bytes[1:] + data


def encode_hke_nonce(E_bytes: bytes, c: bytes) -> bytes:
    return _encode(E_bytes, c, 2, hke.L_c)


def decode_hke_nonce(raw: bytes) -> tuple[bytes, bytes]:
    nonce = parse_nonce(raw)
    if nonce[0] not in (4, 5):
        raise ValueError("expected an HKE nonce")
    return bytes([nonce[0] - 2]) + nonce[1:33], nonce[33:]


def encode_placeholder(B_bytes: bytes, ek: bytes) -> bytes:
    return _encode(B_bytes, ek, 4, hke.L_ek)


def decode_placeholder(raw: bytes) -> tuple[bytes, bytes]:
    nonce = parse_nonce(raw)
    if nonce[0] not in (6, 7):
        raise ValueError("expected an HKE placeholder")
    return bytes([nonce[0] - 4]) + nonce[1:33], nonce[33:]


def validate_output_nonce(raw: bytes, *, hke_active: bool, explicit_value: bool) -> None:
    """Nonce rules for every output, including coinbase outputs."""
    nonce = parse_nonce(raw)
    if nonce[0] in (6, 7):
        raise ValueError("placeholder in a finalized output")
    if nonce[0] in (4, 5):
        if not hke_active:
            raise ValueError("HKE nonce before activation")
        if explicit_value:
            raise ValueError("HKE nonce with an explicit value")


def simplicity_nonce_hash_input(raw: bytes) -> bytes:
    """The nonce contribution to hashing, not a complete Simplicity output hash."""
    nonce = parse_nonce(raw)
    if nonce[0] in (6, 7):
        raise ValueError("placeholder has no consensus hash encoding")
    if nonce[0] in (4, 5):
        return nonce[:33] + sha256(nonce[33:]).digest()
    return nonce


def recover_hke_seed(raw: bytes, msk: bytes) -> bytes | None:
    """Return None for malformed output data; propagate local/backend failures.

    ML-KEM implicit rejection can return a different seed for a modified
    ciphertext. The wallet must still rewind the range proof with this seed.
    """
    if len(msk) != 32:
        raise ValueError("msk must be 32 bytes")
    try:
        E_bytes, c = decode_hke_nonce(raw)
    except ValueError:
        return None
    if hke.lift(E_bytes) is None:
        return None
    return hke.Decaps((E_bytes, c), msk)
