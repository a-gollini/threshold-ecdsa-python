"""Feldman-VSS based distributed key generation (the Joint-Feldman protocol).

Every party deals a random secret; the group key is the sum of all dealt secrets,
so no party (and no dealer) ever knows the full private key.
This in-process simulation stands in for the network round: it is the protocol logic only.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import curve, shamir
from .curve import Point


@dataclass(frozen=True)
class KeyShare:
    """What a single party holds after key generation."""

    index: int
    secret_share: int
    public_key: Point


class DkgComplaintError(Exception):
    def __init__(self, dealer: int, recipient: int) -> None:
        super().__init__(f"Party {recipient} received an invalid share from party {dealer}.")
        self.dealer = dealer
        self.recipient = recipient


def run(threshold: int, parties: int) -> list[KeyShare]:
    # Round 1: each party deals its own random contribution with Feldman commitments.
    dealings = [shamir.deal(curve.random_scalar(), threshold, parties) for _ in range(parties)]

    # Round 2: each recipient verifies every sub-share it received, then sums them.
    secret_shares: list[int] = []
    for recipient in range(parties):
        total = 0
        for dealer, dealing in enumerate(dealings):
            received = dealing.shares[recipient]
            if not shamir.verify(received, dealing.commitments):
                raise DkgComplaintError(dealer + 1, recipient + 1)
            total += received.value
        secret_shares.append(curve.mod(total))

    # The group public key is the sum of each dealer's constant-term commitment.
    public_key = curve.INFINITY
    for dealing in dealings:
        public_key = public_key + dealing.commitments.public_key

    return [KeyShare(i + 1, s, public_key) for i, s in enumerate(secret_shares)]
