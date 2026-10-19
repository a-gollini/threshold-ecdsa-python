import pytest

from threshold_ecdsa import Share, curve, run_dkg, shamir


def _shares(keys, indices):
    return [Share(keys[i].index, keys[i].secret_share) for i in indices]


def test_any_threshold_subset_recovers_the_key_behind_the_public_key():
    keys = run_dkg(threshold=3, parties=5)

    for subset in [(0, 1, 2), (2, 3, 4), (0, 2, 4)]:
        secret = shamir.reconstruct(_shares(keys, subset))
        assert keys[0].public_key == curve.multiply_base(secret)


def test_all_parties_agree_on_the_public_key():
    keys = run_dkg(2, 4)

    assert all(k.public_key == keys[0].public_key for k in keys)


def test_different_subsets_recover_the_same_key():
    keys = run_dkg(2, 4)

    assert shamir.reconstruct(_shares(keys, (0, 1))) == shamir.reconstruct(_shares(keys, (2, 3)))


def test_invalid_parameters_are_rejected():
    with pytest.raises(ValueError):
        run_dkg(threshold=4, parties=3)
