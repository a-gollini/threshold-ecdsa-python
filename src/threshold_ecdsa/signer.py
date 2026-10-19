"""Educational threshold ECDSA over secp256k1, simulated in a single process.

Signing needs 2t-1 online parties, where t is the DKG threshold:
  1. Nonce k and blinding value w are generated with the DKG (shares of degree t-1).
  2. R = k*G is opened from the k shares and r = R.x mod n.
  3. k*w is opened by interpolating the products k_i*w_i (degree 2t-2). Since w is uniform and
     secret, k*w reveals nothing about k, and k^-1 = w * (k*w)^-1 gives shares of k^-1.
  4. Each party sends s_i = kinv_i * (m + r*x_i), a share of s = k^-1 (m + r x) of degree 2t-2.
  5. s is interpolated from the 2t-1 partial signatures.
No step reconstructs k or the private key x.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from . import curve, dkg, shamir
from .curve import Point
from .dkg import KeyShare


@dataclass(frozen=True)
class EcdsaSignature:
    r: int
    s: int


def sign(signers: Sequence[KeyShare], threshold: int, message_hash: bytes) -> EcdsaSignature:
    required = 2 * threshold - 1
    if len(signers) < required:
        raise ValueError(f"At least {required} signers are required for threshold {threshold}.")
    signers = list(signers[:required])
    indices = [s.index for s in signers]
    parties = max(indices)

    m = _hash_to_scalar(message_hash)

    while True:
        # Fresh nonce and blinding shares for the participating parties. A real deployment would
        # run the DKG among the signers over the network; here we reuse the in-process simulation.
        nonce = _select(dkg.run(threshold, parties), indices)
        blind = _select(dkg.run(threshold, parties), indices)

        big_r = nonce[0].public_key
        assert big_r.x is not None
        r = curve.mod(big_r.x)
        if r == 0:
            continue

        kw = _interpolate(indices, [curve.mod(n.secret_share * b.secret_share) for n, b in zip(nonce, blind)])
        if kw == 0:
            continue
        kw_inverse = curve.inverse(kw)

        partials = [
            curve.mod(curve.mod(b.secret_share * kw_inverse) * (m + r * signer.secret_share))
            for signer, b in zip(signers, blind)
        ]

        s = _interpolate(indices, partials)
        if s == 0:
            continue

        # Normalise to low-s (BIP-62 / Bitcoin style) so signatures are non-malleable.
        if s > curve.ORDER // 2:
            s = curve.ORDER - s
        return EcdsaSignature(r, s)


def verify(public_key: Point, message_hash: bytes, signature: EcdsaSignature) -> bool:
    """Standard ECDSA verification: needs only the public key."""
    r, s = signature.r, signature.s
    if not (0 < r < curve.ORDER and 0 < s < curve.ORDER):
        return False
    w = curve.inverse(s)
    point = curve.multiply_base(_hash_to_scalar(message_hash) * w) + curve.multiply(public_key, r * w)
    return not point.is_infinity and point.x is not None and curve.mod(point.x) == r


def _hash_to_scalar(digest: bytes) -> int:
    return curve.mod(int.from_bytes(digest[:32], "big"))


def _select(all_shares: Sequence[KeyShare], indices: Sequence[int]) -> list[KeyShare]:
    return [all_shares[i - 1] for i in indices]


def _interpolate(indices: Sequence[int], values: Sequence[int]) -> int:
    return curve.mod(sum(v * shamir.lagrange_coefficient_at_zero(i, indices) for i, v in zip(indices, values)))
