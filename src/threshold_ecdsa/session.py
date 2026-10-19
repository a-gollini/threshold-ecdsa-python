"""One threshold signing run with verifiable partial results, simulated in a single process.

Every party's public shares are known from the DKGs: K_i = k_i*G (nonce), W_i = w_i*G (blinding),
X_i = x_i*G (key). Nothing a party sends can be wrong without being caught:

  Round 1  party i sends u_i = k_i*w_i.   Anyone computes U_i = u_i*G. The proof shows
           log_G(W_i) = log_{K_i}(U_i) = w_i, i.e. U_i = w_i*K_i, so u_i really is k_i*w_i.
  Round 2  party i sends s_i = w_i * (kw)^-1 * (m + r*x_i). Anyone derives
           T_i = r^-1 * (kw * s_i * G - m * W_i), which equals (w_i*x_i)*G iff s_i is correct.
           The proof shows log_G(W_i) = log_{X_i}(T_i) = w_i, tying s_i to the same blinding share.

A failed proof raises `SigningAbortError` naming the party (identifiable abort).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from . import curve, shamir
from .dkg import KeyShare
from .dleq import DleqProof


@dataclass(frozen=True)
class RoundOneMessage:
    """A party's share u_i = k_i * w_i of k*w, with a proof that it is the right product."""

    index: int
    product: int
    proof: DleqProof


@dataclass(frozen=True)
class RoundTwoMessage:
    """A party's partial signature s_i, with a proof that it was computed from its real shares."""

    index: int
    partial: int
    proof: DleqProof


@dataclass(frozen=True)
class EcdsaSignature:
    r: int
    s: int


class SigningAbortError(Exception):
    """A party sent a message whose proof does not verify: the culprit is identified."""

    def __init__(self, party: int, step: str) -> None:
        super().__init__(f"Party {party} sent an invalid {step}.")
        self.party = party


class DegenerateNonceError(Exception):
    """The random values made the signature degenerate (r, k*w or s is zero): retry with fresh ones."""


class SigningSession:
    def __init__(
        self,
        signers: Sequence[KeyShare],
        nonce: Sequence[KeyShare],
        blind: Sequence[KeyShare],
        message_hash: bytes,
    ) -> None:
        """`signers` are exactly 2t-1 key shares; `nonce` and `blind` are their shares of the nonce k
        and the blinding value w (each from a fresh DKG), in the same order."""
        self._signers = list(signers)
        self._nonce = list(nonce)
        self._blind = list(blind)
        self._indices = [s.index for s in signers]
        self._message_tag = message_hash.hex()
        self._m = curve.hash_to_scalar(message_hash)

        # R = k*G is public (the DKG public key of the nonce), and r is its x coordinate.
        big_r = nonce[0].public_key
        assert big_r.x is not None
        self._r = curve.mod(big_r.x)
        if self._r == 0:
            raise DegenerateNonceError
        self._kw = 0

    def round_one(self) -> list[RoundOneMessage]:
        return [
            RoundOneMessage(
                signer.index,
                curve.mod(k.secret_share * w.secret_share),
                DleqProof.prove(
                    w.secret_share, curve.G, k.public_share_of(signer.index), self._context(1, signer.index)
                ),
            )
            for signer, k, w in zip(self._signers, self._nonce, self._blind)
        ]

    def round_two(self, messages: Sequence[RoundOneMessage]) -> list[RoundTwoMessage]:
        """Verifies every round-1 message, opens k*w, and returns each party's round-2 message."""
        self._check_senders(m.index for m in messages)
        for message, k, w in zip(messages, self._nonce, self._blind):
            product = curve.multiply_base(message.product)
            ok = message.proof.verify(
                curve.G,
                w.public_share_of(message.index),
                k.public_share_of(message.index),
                product,
                self._context(1, message.index),
            )
            if not ok:
                raise SigningAbortError(message.index, "nonce product")

        self._kw = self._interpolate(m.product for m in messages)
        if self._kw == 0:
            raise DegenerateNonceError
        kw_inverse = curve.inverse(self._kw)

        result = []
        for signer, w in zip(self._signers, self._blind):
            k_inverse_share = curve.mod(w.secret_share * kw_inverse)
            partial = curve.mod(k_inverse_share * (self._m + self._r * signer.secret_share))
            proof = DleqProof.prove(
                w.secret_share, curve.G, signer.public_share_of(signer.index), self._context(2, signer.index)
            )
            result.append(RoundTwoMessage(signer.index, partial, proof))
        return result

    def finish(self, messages: Sequence[RoundTwoMessage]) -> EcdsaSignature:
        """Verifies every partial signature and interpolates the final low-s signature."""
        self._check_senders(m.index for m in messages)
        r_inverse = curve.inverse(self._r)
        for message, signer, w in zip(messages, self._signers, self._blind):
            blind_public = w.public_share_of(message.index)
            # T_i = r^-1 * (kw * s_i * G - m * W_i), which is (w_i * x_i) * G exactly when s_i is correct.
            derived = curve.multiply_base(self._kw * message.partial * r_inverse) - curve.multiply(
                blind_public, self._m * r_inverse
            )
            ok = message.proof.verify(
                curve.G,
                blind_public,
                signer.public_share_of(message.index),
                derived,
                self._context(2, message.index),
            )
            if not ok:
                raise SigningAbortError(message.index, "partial signature")

        s = self._interpolate(m.partial for m in messages)
        if s == 0:
            raise DegenerateNonceError

        # Normalise to low-s (BIP-62 / Bitcoin style) so signatures are non-malleable.
        if s > curve.ORDER // 2:
            s = curve.ORDER - s
        return EcdsaSignature(self._r, s)

    def _context(self, round_number: int, index: int) -> str:
        return f"round{round_number}|{index}|{self._message_tag}"

    def _check_senders(self, senders: Iterable[int]) -> None:
        if list(senders) != self._indices:
            raise ValueError("Messages must come from the signing parties, in order.")

    def _interpolate(self, values: Iterable[int]) -> int:
        return curve.mod(
            sum(v * shamir.lagrange_coefficient_at_zero(i, self._indices) for i, v in zip(self._indices, values))
        )
