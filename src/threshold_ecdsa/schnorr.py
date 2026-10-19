"""Non-interactive Schnorr proof of knowledge of the discrete logarithm of a public point P = x*G.

Made non-interactive with Fiat-Shamir. The prover commits to R = v*G, derives c = H(P, R, context)
and answers z = v + c*x; the verifier recomputes R = z*G - c*P and checks the hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import curve
from .curve import Point

_DOMAIN = b"threshold-ecdsa/schnorr/v1"


@dataclass(frozen=True)
class SchnorrProof:
    challenge: int
    response: int

    @staticmethod
    def prove(secret: int, context: str) -> SchnorrProof:
        """`context` binds the proof to one protocol step and one prover so it cannot be replayed."""
        nonce = curve.random_scalar()
        challenge = _challenge(curve.multiply_base(secret), curve.multiply_base(nonce), context)
        return SchnorrProof(challenge, curve.mod(nonce + challenge * secret))

    def verify(self, public_point: Point, context: str) -> bool:
        commitment = curve.multiply_base(self.response) - curve.multiply(public_point, self.challenge)
        return self.challenge == _challenge(public_point, commitment, context)


def _challenge(public_point: Point, commitment: Point, context: str) -> int:
    data = bytearray(_DOMAIN)
    for point in (public_point, commitment):
        data += b"\x00" if point.is_infinity else point.encode()  # SEC1 encodes infinity as one zero byte
    data += context.encode("utf-8")
    return curve.hash_to_scalar(hashlib.sha256(data).digest())
