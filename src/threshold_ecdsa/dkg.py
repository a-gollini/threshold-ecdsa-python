"""Feldman-VSS based distributed key generation (the Joint-Feldman protocol), hardened with proofs of knowledge.

Every party deals a random secret; the group key is the sum of all dealt secrets,
so no party (and no dealer) ever knows the full private key.

Each dealer proves it knows the secret behind its commitment C_0. Without this, the last dealer could pick
C_0 = target - (sum of the others) and steer the group key to a value it does not know the discrete log of
(a rogue-key attack). With the proof it cannot, because it does not know the discrete log of that C_0.
The proof does not prevent the key-distribution bias of Gennaro et al. (see the README).

This in-process simulation stands in for the network rounds: it is the protocol logic only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from . import curve, shamir
from .curve import Point
from .schnorr import SchnorrProof
from .shamir import DealtSecret, FeldmanCommitments, Share


@dataclass(frozen=True)
class KeyShare:
    """What a single party holds after key generation.

    `public_shares` holds the public image x_j * G of every party's share (entry j-1 for party j):
    it is public and lets anyone check proofs about shares.
    """

    index: int
    secret_share: int
    public_key: Point
    public_shares: tuple[Point, ...]

    def public_share_of(self, index: int) -> Point:
        return self.public_shares[index - 1]


@dataclass(frozen=True)
class Dealing:
    """One dealer's round-1 output: Feldman-verifiable shares for everyone, plus a proof that the dealer
    knows the secret behind its constant-term commitment. Commitments and proof are broadcast; share i
    goes to party i."""

    dealer: int
    secret: DealtSecret
    proof: SchnorrProof


@dataclass(frozen=True)
class Complaint:
    """Evidence against a dealer: the share a recipient received and the dealer's broadcast commitments.

    Anyone can check it, so a false accusation is detectable: it is justified only if the share really
    fails Feldman verification. (A real deployment would also need the share to be authenticated as
    coming from the dealer.)"""

    dealer: int
    recipient: int
    share: Share
    commitments: FeldmanCommitments

    @property
    def is_justified(self) -> bool:
        return not shamir.verify(self.share, self.commitments)


class DkgComplaintError(Exception):
    def __init__(self, complaint: Complaint) -> None:
        super().__init__(f"Party {complaint.recipient} received an invalid share from party {complaint.dealer}.")
        self.complaint = complaint
        self.dealer = complaint.dealer
        self.recipient = complaint.recipient


class DkgInvalidDealingError(Exception):
    """A dealer's broadcast is malformed or its proof of knowledge does not verify."""

    def __init__(self, dealer: int, reason: str) -> None:
        super().__init__(f"Party {dealer} sent an invalid dealing: {reason}.")
        self.dealer = dealer


def run(threshold: int, parties: int) -> list[KeyShare]:
    dealings = [deal(dealer, threshold, parties) for dealer in range(1, parties + 1)]
    return complete(dealings, threshold, parties)


def deal(dealer: int, threshold: int, parties: int) -> Dealing:
    """Round 1 for one party: deal a fresh random secret and prove knowledge of it."""
    secret = curve.random_scalar()
    return Dealing(
        dealer,
        shamir.deal(secret, threshold, parties),
        SchnorrProof.prove(secret, _context(dealer, threshold, parties)),
    )


def complete(dealings: Sequence[Dealing], threshold: int, parties: int) -> list[KeyShare]:
    """Round 2: check every broadcast and every received share, then derive each party's key share."""
    if [d.dealer for d in dealings] != list(range(1, parties + 1)):
        raise ValueError("Expected exactly one dealing from each party, in order.")

    for dealing in dealings:
        if len(dealing.secret.commitments.coefficients) != threshold or len(dealing.secret.shares) != parties:
            raise DkgInvalidDealingError(dealing.dealer, "wrong number of commitments or shares")
        if not dealing.proof.verify(dealing.secret.commitments.public_key, _context(dealing.dealer, threshold, parties)):
            raise DkgInvalidDealingError(dealing.dealer, "proof of knowledge does not verify")

    # Each recipient verifies every sub-share it received, then sums them.
    secret_shares: list[int] = []
    for recipient in range(parties):
        total = 0
        for dealing in dealings:
            received = dealing.secret.shares[recipient]
            if not shamir.verify(received, dealing.secret.commitments):
                raise DkgComplaintError(
                    Complaint(dealing.dealer, recipient + 1, received, dealing.secret.commitments)
                )
            total += received.value
        secret_shares.append(curve.mod(total))

    # Summing every dealer's commitments coefficient-wise gives commitments to the group polynomial.
    # Its constant term is the group public key, and evaluating it at i gives party i's public share.
    group_commitments = FeldmanCommitments(
        tuple(
            sum((d.secret.commitments.coefficients[j] for d in dealings), curve.INFINITY)
            for j in range(threshold)
        )
    )
    public_key = group_commitments.public_key
    public_shares = tuple(shamir.public_share(i, group_commitments) for i in range(1, parties + 1))

    return [KeyShare(i + 1, s, public_key, public_shares) for i, s in enumerate(secret_shares)]


def _context(dealer: int, threshold: int, parties: int) -> str:
    return f"dkg|{dealer}|{threshold}|{parties}"
