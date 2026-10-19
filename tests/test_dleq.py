from dataclasses import replace

from threshold_ecdsa import DleqProof, curve

BASE2 = curve.multiply_base(curve.random_scalar())


def test_valid_proof_verifies():
    w = curve.random_scalar()
    proof = DleqProof.prove(w, curve.G, BASE2, "ctx")

    assert proof.verify(curve.G, curve.multiply_base(w), BASE2, curve.multiply(BASE2, w), "ctx")


def test_different_discrete_logs_are_rejected():
    w = curve.random_scalar()
    proof = DleqProof.prove(w, curve.G, BASE2, "ctx")
    wrong_second = curve.multiply(BASE2, curve.mod(w + 1))

    assert not proof.verify(curve.G, curve.multiply_base(w), BASE2, wrong_second, "ctx")


def test_proof_is_bound_to_its_context():
    w = curve.random_scalar()
    proof = DleqProof.prove(w, curve.G, BASE2, "round1|1")

    assert not proof.verify(curve.G, curve.multiply_base(w), BASE2, curve.multiply(BASE2, w), "round1|2")


def test_tampered_response_is_rejected():
    w = curve.random_scalar()
    proof = DleqProof.prove(w, curve.G, BASE2, "ctx")
    tampered = replace(proof, response=curve.mod(proof.response + 1))

    assert not tampered.verify(curve.G, curve.multiply_base(w), BASE2, curve.multiply(BASE2, w), "ctx")
