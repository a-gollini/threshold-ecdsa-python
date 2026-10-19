"""Educational threshold ECDSA on secp256k1. Not for production use."""

from .dkg import DkgComplaintError, KeyShare
from .dkg import run as run_dkg
from .shamir import DealtSecret, FeldmanCommitments, Share
from .signer import EcdsaSignature, sign, verify

__all__ = [
    "DealtSecret",
    "DkgComplaintError",
    "EcdsaSignature",
    "FeldmanCommitments",
    "KeyShare",
    "Share",
    "run_dkg",
    "sign",
    "verify",
]
