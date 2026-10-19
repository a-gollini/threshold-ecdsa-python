"""secp256k1 parameters, point arithmetic and scalar helpers (arithmetic modulo the group order)."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    """An affine point on y^2 = x^3 + 7; `None` coordinates encode the point at infinity."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __add__(self, other: Point) -> Point:
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        assert self.x is not None and self.y is not None
        assert other.x is not None and other.y is not None
        if self.x == other.x:
            if (self.y + other.y) % P == 0:
                return INFINITY
            slope = 3 * self.x * self.x * pow(2 * self.y, -1, P) % P
        else:
            slope = (other.y - self.y) * pow(other.x - self.x, -1, P) % P
        x = (slope * slope - self.x - other.x) % P
        return Point(x, (slope * (self.x - x) - self.y) % P)

    def encode(self) -> bytes:
        """SEC1 compressed encoding (33 bytes)."""
        if self.x is None or self.y is None:
            raise ValueError("cannot encode the point at infinity")
        return bytes([2 + (self.y & 1)]) + self.x.to_bytes(32, "big")


INFINITY = Point(None, None)
G = Point(_GX, _GY)


def mod(value: int) -> int:
    return value % ORDER


def inverse(value: int) -> int:
    return pow(mod(value), -1, ORDER)


def random_scalar() -> int:
    """Uniform random scalar in [1, n-1] using the OS CSPRNG (rejection sampling)."""
    while True:
        candidate = secrets.randbits(256)
        if 0 < candidate < ORDER:
            return candidate


def multiply(point: Point, scalar: int) -> Point:
    """Double-and-add scalar multiplication. Not constant time: educational use only."""
    scalar = mod(scalar)
    result = INFINITY
    addend = point
    while scalar:
        if scalar & 1:
            result = result + addend
        addend = addend + addend
        scalar >>= 1
    return result


def multiply_base(scalar: int) -> Point:
    return multiply(G, scalar)
