"""Today's Liquid/Elements confidential segwit address — the format the
HKE confidential address (`address.py`) extends.

Structure and constants below are read directly from the Elements source
(`src/key_io.cpp`, `DestinationEncoder`/`DecodeDestination`, and
`src/chainparams.cpp` for the per-network HRPs), not reconstructed from
the ELIP's summary of it:

- payload = `witver || convertbits(blinding_pubkey(33B) || witness_program, 8, 5)`
- checksum variant depends on witness version: v0 -> blech32, v1+ (e.g.
  Taproot) -> blech32m (key_io.cpp lines ~70-138, ~304-310).
- witness program is 20 bytes (P2WPKH) or 32 bytes (P2WSH) for v0.
- HRPs (chainparams.cpp): "lq" Liquid mainnet, "tlq" Liquid testnet,
  "el" Elements-style regtest/custom chains (e.g. elements-cli regtest,
  `CCustomParams`).

This intentionally does *not* reuse blech32m.py's `encode_segwit`'s witver=0
default silently — callers pick the network HRP and witness version
explicitly, since a real wallet would derive both from context (network,
script type), not assume them.
"""

from dataclasses import dataclass

import blech32m

HRP_MAINNET = "lq"
HRP_TESTNET = "tlq"
HRP_REGTEST = "el"

WITVER_V0 = 0  # P2WPKH / P2WSH
WITVER_V1_TAPROOT = 1

B_LEN = 33
P2WPKH_PROGRAM_LEN = 20
P2WSH_PROGRAM_LEN = 32


@dataclass
class ClassicalConfidentialAddress:
    B: bytes
    program: bytes
    witver: int = WITVER_V0

    def encode(self, hrp: str) -> str:
        return blech32m.encode_segwit(hrp, self.witver, self.B + self.program)


def decode_classical_address(addr: str, hrp: str) -> ClassicalConfidentialAddress:
    witver, payload = blech32m.decode_segwit(addr, expected_hrp=hrp)
    if len(payload) < B_LEN + 2:
        raise ValueError("payload too short to contain a blinding pubkey and witness program")
    B = payload[:B_LEN]
    program = payload[B_LEN:]
    if witver == WITVER_V0 and len(program) not in (P2WPKH_PROGRAM_LEN, P2WSH_PROGRAM_LEN):
        raise ValueError(f"invalid v0 witness program length {len(program)} (expected 20 or 32)")
    if len(program) < 2 or len(program) > 40:
        raise ValueError(f"invalid witness program length {len(program)}")
    return ClassicalConfidentialAddress(B=B, program=program, witver=witver)
