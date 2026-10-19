from dataclasses import replace

import pytest

from threshold_ecdsa import curve, shamir


def test_any_threshold_subset_reconstructs_secret():
    secret = curve.random_scalar()
    dealt = shamir.deal(secret, threshold=3, parties=5)

    for subset in [(0, 1, 2), (1, 3, 4), (0, 2, 4)]:
        assert shamir.reconstruct([dealt.shares[i] for i in subset]) == secret


def test_below_threshold_does_not_reconstruct_secret():
    secret = curve.random_scalar()
    dealt = shamir.deal(secret, threshold=3, parties=5)

    assert shamir.reconstruct(dealt.shares[:2]) != secret


def test_feldman_verification_accepts_valid_and_rejects_tampered_shares():
    dealt = shamir.deal(curve.random_scalar(), threshold=2, parties=4)

    assert all(shamir.verify(s, dealt.commitments) for s in dealt.shares)

    tampered = replace(dealt.shares[0], value=curve.mod(dealt.shares[0].value + 1))
    assert not shamir.verify(tampered, dealt.commitments)


def test_commitments_expose_the_public_key():
    secret = curve.random_scalar()
    dealt = shamir.deal(secret, 2, 3)

    assert dealt.commitments.public_key == curve.multiply_base(secret)


def test_duplicate_indices_are_rejected():
    dealt = shamir.deal(curve.random_scalar(), 2, 3)

    with pytest.raises(ValueError):
        shamir.reconstruct([dealt.shares[0], dealt.shares[0]])
