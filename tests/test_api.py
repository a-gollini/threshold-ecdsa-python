import uuid

import pytest
from fastapi.testclient import TestClient

from threshold_ecdsa.api.app import create_app


@pytest.fixture
def client():
    return TestClient(create_app())


def _create_key(client, threshold=2, parties=3):
    response = client.post("/keys", json={"threshold": threshold, "parties": parties})
    assert response.status_code == 201
    return response.json()


def test_create_key_returns_compressed_public_key(client):
    key = _create_key(client)

    assert len(key["public_key"]) == 66
    assert key["public_key"][:2] in ("02", "03")


def test_sign_then_verify_round_trips(client):
    key = _create_key(client)
    signature = client.post(f"/keys/{key['key_id']}/sign", json={"message": "hello"}).json()

    def check(message):
        body = {"message": message, "r": signature["r"], "s": signature["s"]}
        return client.post(f"/keys/{key['key_id']}/verify", json=body).json()["valid"]

    assert check("hello") is True
    assert check("hellO") is False


def test_signatures_are_always_64_hex_characters(client):
    key = _create_key(client)

    for i in range(30):
        signature = client.post(f"/keys/{key['key_id']}/sign", json={"message": f"message {i}"}).json()
        assert len(signature["r"]) == 64
        assert len(signature["s"]) == 64


@pytest.mark.parametrize(("threshold", "parties"), [(0, 3), (3, 4), (2, 100)])
def test_create_key_rejects_invalid_parameters(client, threshold, parties):
    response = client.post("/keys", json={"threshold": threshold, "parties": parties})

    assert response.status_code == 400


def test_unknown_key_returns_404(client):
    unknown = uuid.uuid4()

    assert client.get(f"/keys/{unknown}").status_code == 404
    assert client.post(f"/keys/{unknown}/sign", json={"message": "x"}).status_code == 404


def test_sign_requires_message(client):
    key = _create_key(client)

    assert client.post(f"/keys/{key['key_id']}/sign", json={"message": ""}).status_code == 400


def test_verify_rejects_malformed_hex(client):
    key = _create_key(client)

    response = client.post(f"/keys/{key['key_id']}/verify", json={"message": "m", "r": "zz", "s": "01"})

    assert response.status_code == 400
