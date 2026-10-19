import hashlib
from dataclasses import replace

import pytest

from threshold_ecdsa import SigningAbortError, SigningSession, curve, run_dkg, verify

THRESHOLD = 2
HASH = hashlib.sha256(b"pay 1 BTC to alice").digest()


def _new_session(message_hash: bytes = HASH, keys=None):
    keys = keys or run_dkg(THRESHOLD, 3)
    return keys, SigningSession(keys, run_dkg(THRESHOLD, 3), run_dkg(THRESHOLD, 3), message_hash)


def test_honest_parties_produce_a_valid_signature():
    keys, session = _new_session()

    signature = session.finish(session.round_two(session.round_one()))

    assert verify(keys[0].public_key, HASH, signature)


def test_public_shares_match_the_secret_shares_and_are_shared_by_all_parties():
    keys = run_dkg(3, 5)

    for key in keys:
        assert curve.multiply_base(key.secret_share) == keys[0].public_share_of(key.index)
        assert key.public_shares == keys[0].public_shares


def test_wrong_nonce_product_identifies_the_cheating_party():
    _, session = _new_session()
    messages = session.round_one()
    messages[1] = replace(messages[1], product=curve.mod(messages[1].product + 1))

    with pytest.raises(SigningAbortError) as abort:
        session.round_two(messages)

    assert abort.value.party == 2


def test_proof_copied_from_another_party_is_rejected():
    _, session = _new_session()
    messages = session.round_one()
    messages[2] = replace(messages[2], proof=messages[0].proof)

    with pytest.raises(SigningAbortError) as abort:
        session.round_two(messages)

    assert abort.value.party == 3


def test_wrong_partial_signature_identifies_the_cheating_party():
    _, session = _new_session()
    messages = session.round_two(session.round_one())
    messages[0] = replace(messages[0], partial=curve.mod(messages[0].partial + 1))

    with pytest.raises(SigningAbortError) as abort:
        session.finish(messages)

    assert abort.value.party == 1


def test_party_using_a_different_key_share_than_it_committed_to_is_identified():
    # Party 2 computes a perfectly well-formed s_2, but from a secret share that does not match
    # its public share from the DKG. Only the proof against the public share can catch this.
    keys = run_dkg(THRESHOLD, 3)
    cheater = list(keys)
    cheater[1] = replace(cheater[1], secret_share=curve.random_scalar())
    _, session = _new_session(keys=cheater)

    with pytest.raises(SigningAbortError) as abort:
        session.finish(session.round_two(session.round_one()))

    assert abort.value.party == 2


def test_round_two_proofs_are_bound_to_the_message():
    _, first = _new_session()
    _, second = _new_session(hashlib.sha256(b"a different message").digest())
    stolen = first.round_two(first.round_one())

    second.round_two(second.round_one())
    with pytest.raises(SigningAbortError):
        second.finish(stolen)


def test_messages_from_the_wrong_parties_are_rejected():
    _, session = _new_session()

    with pytest.raises(ValueError):
        session.round_two(list(reversed(session.round_one())))
