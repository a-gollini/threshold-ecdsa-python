from dataclasses import replace

import pytest

from threshold_ecdsa import SchnorrProof, curve, dkg
from threshold_ecdsa.dkg import Complaint, DkgComplaintError, DkgInvalidDealingError
from threshold_ecdsa.shamir import FeldmanCommitments

THRESHOLD = 2
PARTIES = 4


def _honest_dealings():
    return [dkg.deal(d, THRESHOLD, PARTIES) for d in range(1, PARTIES + 1)]


def test_honest_dealings_complete_and_agree_on_the_key():
    keys = dkg.complete(_honest_dealings(), THRESHOLD, PARTIES)

    assert len(keys) == PARTIES
    assert all(k.public_key == keys[0].public_key for k in keys)


def test_schnorr_proof_verifies_and_is_bound_to_its_context():
    secret = curve.random_scalar()
    proof = SchnorrProof.prove(secret, "dkg|1")

    assert proof.verify(curve.multiply_base(secret), "dkg|1")
    assert not proof.verify(curve.multiply_base(secret), "dkg|2")
    assert not proof.verify(curve.multiply_base(curve.mod(secret + 1)), "dkg|1")


def test_proof_for_a_different_secret_is_rejected():
    dealings = _honest_dealings()
    dealings[2] = replace(dealings[2], proof=SchnorrProof.prove(curve.random_scalar(), "dkg|3|2|4"))

    with pytest.raises(DkgInvalidDealingError) as error:
        dkg.complete(dealings, THRESHOLD, PARTIES)

    assert error.value.dealer == 3


def test_proof_replayed_from_another_dealer_is_rejected():
    dealings = _honest_dealings()
    dealings[1] = replace(dealings[1], proof=dealings[0].proof)

    with pytest.raises(DkgInvalidDealingError) as error:
        dkg.complete(dealings, THRESHOLD, PARTIES)

    assert error.value.dealer == 2


def test_rogue_key_attack_is_rejected():
    # The last dealer tries to steer the group key to a point it does not know the discrete log of,
    # by choosing C_0 = target - (sum of the other C_0). It cannot prove knowledge of that C_0's secret.
    dealings = _honest_dealings()
    target = curve.multiply_base(curve.random_scalar())
    others = curve.INFINITY
    for d in dealings[:-1]:
        others = others + d.secret.commitments.public_key
    rogue = dealings[-1]
    coefficients = (target - others,) + rogue.secret.commitments.coefficients[1:]
    dealings[-1] = replace(rogue, secret=replace(rogue.secret, commitments=FeldmanCommitments(coefficients)))

    with pytest.raises(DkgInvalidDealingError) as error:
        dkg.complete(dealings, THRESHOLD, PARTIES)

    assert error.value.dealer == PARTIES


def test_malformed_dealing_is_rejected():
    dealings = _honest_dealings()
    short = FeldmanCommitments(dealings[0].secret.commitments.coefficients[:1])
    dealings[0] = replace(dealings[0], secret=replace(dealings[0].secret, commitments=short))

    with pytest.raises(DkgInvalidDealingError) as error:
        dkg.complete(dealings, THRESHOLD, PARTIES)

    assert error.value.dealer == 1


def test_invalid_share_produces_a_complaint_that_anyone_can_check():
    dealings = _honest_dealings()
    shares = list(dealings[1].secret.shares)
    shares[2] = replace(shares[2], value=curve.mod(shares[2].value + 1))
    dealings[1] = replace(dealings[1], secret=replace(dealings[1].secret, shares=tuple(shares)))

    with pytest.raises(DkgComplaintError) as error:
        dkg.complete(dealings, THRESHOLD, PARTIES)

    assert (error.value.dealer, error.value.recipient) == (2, 3)
    assert error.value.complaint.is_justified


def test_false_complaint_against_an_honest_dealer_is_not_justified():
    dealing = _honest_dealings()[0]

    complaint = Complaint(1, 2, dealing.secret.shares[1], dealing.secret.commitments)

    assert not complaint.is_justified
