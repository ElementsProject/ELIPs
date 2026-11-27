"""HKE confidential address (`elip-hke-confidential-transactions.mediawiki`, "HKE
confidential address") — encoding, decoding, and QR rendering.

Format: `hrp || "1" || base32(payload || CRC32(hrp || payload))`, with
`payload = hke_version || witver || B || ek || program`. `base32` uses the
bech32 alphabet; the checksum is CRC-32 (zlib), not bech32's BCH code.

HRP `"el2"` is the regtest HRP proposed by the ELIP (subject to registration);
`hke_version = 0x01` is HKE v1 / ML-KEM-768.
"""

import zlib
from dataclasses import dataclass

import qrcode

from blech32m import CHARSET, convertbits
from hke import KEM, lift

HRP = "el2"
HKE_VERSION = 0x01
B_LEN = 33
EK_LEN = 1184  # ML-KEM-768 encapsulation key size (elip-0222.mediawiki L_ek)


def witness_script_pubkey(witver: int, program: bytes) -> bytes:
    """`OP_n <program>` for witness version `witver`."""
    assert 0 <= witver <= 16 and 2 <= len(program) <= 40
    op = 0x00 if witver == 0 else 0x50 + witver
    return bytes([op, len(program)]) + program


def is_valid_witness_program(witver: int, program: bytes) -> bool:
    """BIP141 rules: version 0-16, 2-40 bytes, version 0 only 20 or 32 bytes."""
    if witver > 16 or not 2 <= len(program) <= 40:
        return False
    return witver != 0 or len(program) in (20, 32)


def crc32(hrp: str, payload: bytes) -> bytes:
    """CRC-32/ISO-HDLC of `hrp || payload`, 4 bytes big-endian."""
    return zlib.crc32(hrp.encode("ascii") + payload).to_bytes(4, "big")


def base32_encode(data: bytes) -> str:
    """8-to-5 regrouping, MSB first, zero-padded final group."""
    return "".join(CHARSET[d] for d in convertbits(list(data), 8, 5, pad=True))


def base32_decode(s: str) -> bytes:
    """Inverse of `base32_encode`; rejects bad characters and noncanonical padding."""
    values = []
    for ch in s:
        i = CHARSET.find(ch)
        if i < 0:
            raise ValueError(f"invalid character {ch!r}")
        values.append(i)
    data = convertbits(values, 5, 8, pad=False)
    if data is None:
        raise ValueError("invalid padding")
    return bytes(data)


@dataclass
class HKEConfidentialAddress:
    B: bytes
    ek: bytes
    witver: int
    program: bytes

    def script_pubkey(self) -> bytes:
        return witness_script_pubkey(self.witver, self.program)

    def payload(self) -> bytes:
        return bytes([HKE_VERSION, self.witver]) + self.B + self.ek + self.program

    def encode(self) -> str:
        payload = self.payload()
        return HRP + "1" + base32_encode(payload + crc32(HRP, payload))


def decode_address(addr: str) -> HKEConfidentialAddress:
    if addr != addr.lower() and addr != addr.upper():
        raise ValueError("mixed-case address")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1:
        raise ValueError("missing separator")
    hrp, data = addr[:pos], base32_decode(addr[pos + 1:])
    if hrp != HRP:
        raise ValueError(f"unexpected human-readable part {hrp!r} (expected {HRP!r})")
    if len(data) < 4:
        raise ValueError("address too short")
    payload, checksum = data[:-4], data[-4:]
    if crc32(hrp, payload) != checksum:
        raise ValueError("invalid HKE confidential address (bad checksum)")
    if len(payload) < 1:
        raise ValueError("address too short")
    if payload[0] != HKE_VERSION:
        raise ValueError(f"unsupported hke_version 0x{payload[0]:02x}")
    if len(payload) < 2 + B_LEN + EK_LEN:
        raise ValueError("address too short")
    witver = payload[1]
    B = payload[2:2 + B_LEN]
    ek = payload[2 + B_LEN:2 + B_LEN + EK_LEN]
    program = payload[2 + B_LEN + EK_LEN:]
    if not is_valid_witness_program(witver, program):
        raise ValueError(f"invalid witness version {witver} / program length {len(program)}")
    if lift(B) is None:
        raise ValueError("B is not a valid compressed point")
    if not KEM.CheckEK(ek):
        raise ValueError("ek fails the FIPS 203 encapsulation key check")
    return HKEConfidentialAddress(B=B, ek=ek, witver=witver, program=program)


def render_qr(address_str: str, path: str) -> int:
    """Writes a QR-code PNG for the address string. Returns the QR version used.

    Encodes uppercase so the `qrcode` library selects QR's alphanumeric mode
    (the bech32 alphabet is a subset of QR's alphanumeric charset once
    uppercased), which is denser than byte mode.
    """
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(address_str.upper())
    qr.make(fit=True)
    img = qr.make_image()
    img.save(path)
    return qr.version
