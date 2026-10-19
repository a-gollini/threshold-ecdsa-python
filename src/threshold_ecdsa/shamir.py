"""Shamir secret sharing over the secp256k1 scalar field, with Feldman verifiability."""

from __future__ import annotations

from dataclasses import dataclass
from functools import reduce
from typing import Sequence

from . import curve
from .curve import Point


@dataclass(frozen=True)
class Share:
    index: int
    value: int


@dataclass(frozen=True)
class FeldmanCommitments:
    """C_j = a_j * G for each polynomial coefficient a_j."""

    coefficients: tuple[Point, ...]

    @property
    def public_key(self) -> Point:
        return self.coefficients[0]


@dataclass(frozen=True)
class DealtSecret:
    shares: tuple[Share, ...]
    commitments: FeldmanCommitments


def deal(secret: int, threshold: int, parties: int) -> DealtSecret:
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if parties < threshold:
        raise ValueError("parties must be >= threshold")

    # f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}, with a_0 = secret.
    coefficients = [curve.mod(secret)] + [curve.random_scalar() for _ in range(threshold - 1)]

    shares = tuple(Share(x, _evaluate(coefficients, x)) for x in range(1, parties + 1))
    commitments = FeldmanCommitments(tuple(curve.multiply_base(a) for a in coefficients))
    return DealtSecret(shares, commitments)


def verify(share: Share, commitments: FeldmanCommitments) -> bool:
    """Checks s_i * G == sum_j (i^j * C_j)."""
    expected = commitments.coefficients[0]
    power = 1
    for commitment in commitments.coefficients[1:]:
        power = curve.mod(power * share.index)
        expected = expected + curve.multiply(commitment, power)
    return curve.multiply_base(share.value) == expected


def reconstruct(shares: Sequence[Share]) -> int:
    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate share indices")
    return curve.mod(sum(s.value * lagrange_coefficient_at_zero(s.index, indices) for s in shares))


def lagrange_coefficient_at_zero(index: int, participants: Sequence[int]) -> int:
    others = [j for j in participants if j != index]
    numerator = reduce(lambda acc, j: curve.mod(acc * -j), others, 1)
    denominator = reduce(lambda acc, j: curve.mod(acc * (index - j)), others, 1)
    return curve.mod(numerator * curve.inverse(denominator))


def _evaluate(coefficients: Sequence[int], x: int) -> int:
    # Horner's method.
    result = 0
    for coefficient in reversed(coefficients):
        result = curve.mod(result * x + coefficient)
    return result


__all__ = [
    "DealtSecret",
    "FeldmanCommitments",
    "Share",
    "deal",
    "lagrange_coefficient_at_zero",
    "reconstruct",
    "verify",
]
