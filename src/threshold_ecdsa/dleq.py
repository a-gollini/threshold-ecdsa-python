"""Non-interactive Chaum-Pedersen proof that two points share the same discrete logarithm.

P1 = w * B1 and P2 = w * B2 for one secret w, without revealing w. Made non-interactive with Fiat-Shamir.

The prover commits to V1 = v*B1, V2 = v*B2 for a random v, derives the challenge c = H(statement, V1, V2)
and answers z = v + c*w. The verifier recomputes V1 = z*B1 - c*P1 and V2 = z*B2 - c*P2 and checks the hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import curve
from .curve import Point

_DOMAIN = b"threshold-ecdsa/dleq/v1"


@dataclass(frozen=True)
class DleqProof:
    challenge: int
    response: int

    @staticmethod
    def prove(secret: int, base1: Point, base2: Point, context: str) -> DleqProof:
        """`context` binds the proof to one protocol step so it cannot be replayed elsewhere."""
        public1 = curve.multiply(base1, secret)
        public2 = curve.multiply(base2, secret)
        nonce = curve.random_scalar()
        challenge = _challenge(
            base1, public1, base2, public2, curve.multiply(base1, nonce), curve.multiply(base2, nonce), context
        )
        return DleqProof(challenge, curve.mod(nonce + challenge * secret))

    def verify(self, base1: Point, public1: Point, base2: Point, public2: Point, context: str) -> bool:
        commitment1 = curve.multiply(base1, self.response) - curve.multiply(public1, self.challenge)
        commitment2 = curve.multiply(base2, self.response) - curve.multiply(public2, self.challenge)
        return self.challenge == _challenge(base1, public1, base2, public2, commitment1, commitment2, context)


def _challenge(*points_and_context: Point | str) -> int:
    data = bytearray(_DOMAIN)
    for part in points_and_context:
        if isinstance(part, Point):
            data += b"\x00" if part.is_infinity else part.encode()  # SEC1 encodes infinity as one zero byte
        else:
            data += part.encode("utf-8")
    return curve.hash_to_scalar(hashlib.sha256(data).digest())
