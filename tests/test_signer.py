import hashlib

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from threshold_ecdsa import EcdsaSignature, curve, run_dkg, sign, verify


def _hash(message: str) -> bytes:
    return hashlib.sha256(message.encode()).digest()


@pytest.mark.parametrize(("threshold", "parties"), [(2, 3), (2, 5), (3, 5)])
def test_threshold_signature_verifies_as_standard_ecdsa(threshold, parties):
    keys = run_dkg(threshold, parties)
    digest = _hash("pay 1 BTC to alice")

    signature = sign(keys, threshold, digest)

    assert verify(keys[0].public_key, digest, signature)


def test_signature_is_accepted_by_an_independent_ecdsa_implementation():
    keys = run_dkg(2, 3)
    digest = _hash("independent check")
    signature = sign(keys, 2, digest)

    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), keys[0].public_key.encode())
    der = utils.encode_dss_signature(signature.r, signature.s)

    public_key.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    with pytest.raises(InvalidSignature):
        public_key.verify(der, _hash("other"), ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_signature_does_not_verify_for_a_different_message():
    keys = run_dkg(2, 3)
    signature = sign(keys, 2, _hash("message A"))

    assert not verify(keys[0].public_key, _hash("message B"), signature)


def test_out_of_range_signature_is_rejected():
    keys = run_dkg(2, 3)

    assert not verify(keys[0].public_key, _hash("x"), EcdsaSignature(0, 1))
    assert not verify(keys[0].public_key, _hash("x"), EcdsaSignature(1, curve.ORDER))


def test_signature_is_low_s():
    keys = run_dkg(2, 3)

    for i in range(20):
        assert sign(keys, 2, _hash(f"m{i}")).s <= curve.ORDER // 2


def test_too_few_signers_are_rejected():
    keys = run_dkg(3, 5)

    with pytest.raises(ValueError):
        sign(keys[:4], 3, _hash("x"))
