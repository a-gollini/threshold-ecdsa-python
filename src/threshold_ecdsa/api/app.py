"""REST API: run a DKG, sign with a threshold of parties, verify with standard ECDSA."""

from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel

from ..signer import EcdsaSignature
from .service import KeyService, hash_message

MAX_PARTIES = 20


class CreateKeyRequest(BaseModel):
    threshold: int
    parties: int


class KeyResponse(BaseModel):
    key_id: uuid.UUID
    threshold: int
    parties: int
    public_key: str


class SignRequest(BaseModel):
    message: str


class SignatureResponse(BaseModel):
    r: str
    s: str
    message_hash: str


class VerifyRequest(BaseModel):
    message: str = ""
    r: str
    s: str


class VerifyResponse(BaseModel):
    valid: bool


def create_app() -> FastAPI:
    app = FastAPI(title="threshold-ecdsa-python", version="1.0.0")
    service = KeyService()

    def get_service() -> KeyService:
        return service

    def get_key(key_id: uuid.UUID, svc: KeyService = Depends(get_service)):
        key = svc.find(key_id)
        if key is None:
            raise HTTPException(status_code=404, detail="Key not found.")
        return key

    @app.post("/keys", status_code=201, response_model=KeyResponse, tags=["Keys"],
              summary="Run distributed key generation among simulated parties.")
    def create_key(request: CreateKeyRequest, svc: KeyService = Depends(get_service)):
        needed = 2 * request.threshold - 1
        if request.threshold < 1 or request.parties < needed or request.parties > MAX_PARTIES:
            raise HTTPException(
                status_code=400,
                detail=f"parties must be between {needed} (2t-1, needed to sign) and {MAX_PARTIES}, "
                       "and threshold must be >= 1.",
            )
        key = svc.create_key(request.threshold, request.parties)
        return _to_response(key)

    @app.get("/keys/{key_id}", response_model=KeyResponse, tags=["Keys"],
             summary="Get the public information of a generated key.")
    def read_key(key=Depends(get_key)):
        return _to_response(key)

    @app.post("/keys/{key_id}/sign", response_model=SignatureResponse, tags=["Keys"],
              summary="Sign SHA-256(message) with a threshold of parties.")
    def sign(request: SignRequest, key=Depends(get_key), svc: KeyService = Depends(get_service)):
        if not request.message:
            raise HTTPException(status_code=400, detail="message is required.")
        signature = svc.sign(key, request.message)
        return SignatureResponse(
            r=_to_hex(signature.r), s=_to_hex(signature.s),
            message_hash=hash_message(request.message).hex(),
        )

    @app.post("/keys/{key_id}/verify", response_model=VerifyResponse, tags=["Keys"],
              summary="Verify a signature with standard ECDSA.")
    def verify(request: VerifyRequest, key=Depends(get_key), svc: KeyService = Depends(get_service)):
        r, s = _parse_hex(request.r), _parse_hex(request.s)
        if r is None or s is None:
            raise HTTPException(status_code=400, detail="r and s must be hex-encoded.")
        return VerifyResponse(valid=svc.verify(key, request.message, EcdsaSignature(r, s)))

    return app


def _to_response(key) -> KeyResponse:
    return KeyResponse(key_id=key.id, threshold=key.threshold, parties=key.parties, public_key=key.public_key_hex)


def _to_hex(value: int) -> str:
    return f"{value:064x}"


def _parse_hex(text: str) -> int | None:
    if not text or len(text) > 64:
        return None
    try:
        return int(text, 16) if all(c in "0123456789abcdefABCDEF" for c in text) else None
    except ValueError:
        return None


app = create_app()
