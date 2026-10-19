"""Educational threshold ECDSA over secp256k1, simulated in a single process.

Signing needs 2t-1 online parties, where t is the DKG threshold:
  1. Nonce k and blinding value w are generated with the DKG (shares of degree t-1).
  2. R = k*G is opened from the k shares and r = R.x mod n.
  3. k*w is opened by interpolating the products k_i*w_i (degree 2t-2). Since w is uniform and
     secret, k*w reveals nothing about k, and k^-1 = w * (k*w)^-1 gives shares of k^-1.
  4. Each party sends s_i = kinv_i * (m + r*x_i), a share of s = k^-1 (m + r x) of degree 2t-2.
  5. s is interpolated from the 2t-1 partial signatures.
No step reconstructs k or the private key x. Steps 3 and 4 carry zero-knowledge proofs, so a party
that sends a wrong value is identified (see `session.SigningSession`).
"""

from __future__ import annotations

from typing import Sequence

from . import curve, dkg
from .curve import Point
from .dkg import KeyShare
from .session import DegenerateNonceError, EcdsaSignature, SigningSession


def sign(signers: Sequence[KeyShare], threshold: int, message_hash: bytes) -> EcdsaSignature:
    required = 2 * threshold - 1
    if len(signers) < required:
        raise ValueError(f"At least {required} signers are required for threshold {threshold}.")
    signers = list(signers[:required])
    indices = [s.index for s in signers]
    parties = max(indices)

    while True:
        # Fresh nonce and blinding shares for the participating parties. A real deployment would
        # run the DKG among the signers over the network; here we reuse the in-process simulation.
        nonce = _select(dkg.run(threshold, parties), indices)
        blind = _select(dkg.run(threshold, parties), indices)

        try:
            session = SigningSession(signers, nonce, blind, message_hash)
            return session.finish(session.round_two(session.round_one()))
        except DegenerateNonceError:
            continue  # probability about 2^-256 per attempt; draw fresh randomness


def verify(public_key: Point, message_hash: bytes, signature: EcdsaSignature) -> bool:
    """Standard ECDSA verification: needs only the public key."""
    r, s = signature.r, signature.s
    if not (0 < r < curve.ORDER and 0 < s < curve.ORDER):
        return False
    w = curve.inverse(s)
    point = curve.multiply_base(curve.hash_to_scalar(message_hash) * w) + curve.multiply(public_key, r * w)
    return not point.is_infinity and point.x is not None and curve.mod(point.x) == r


def _select(all_shares: Sequence[KeyShare], indices: Sequence[int]) -> list[KeyShare]:
    return [all_shares[i - 1] for i in indices]
