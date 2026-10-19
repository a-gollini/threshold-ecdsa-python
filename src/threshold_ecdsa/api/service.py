"""Application layer: orchestrates the core library.

All parties are simulated in-process, so shares live in memory only and are lost on
restart (by design for this demo).
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass

from .. import dkg, signer
from ..dkg import KeyShare
from ..signer import EcdsaSignature


@dataclass(frozen=True)
class StoredKey:
    id: uuid.UUID
    threshold: int
    shares: tuple[KeyShare, ...]

    @property
    def parties(self) -> int:
        return len(self.shares)

    @property
    def public_key_hex(self) -> str:
        return self.shares[0].public_key.encode().hex()


def hash_message(message: str) -> bytes:
    return hashlib.sha256(message.encode("utf-8")).digest()


class KeyService:
    def __init__(self) -> None:
        self._keys: dict[uuid.UUID, StoredKey] = {}
        self._lock = threading.Lock()

    def create_key(self, threshold: int, parties: int) -> StoredKey:
        key = StoredKey(uuid.uuid4(), threshold, tuple(dkg.run(threshold, parties)))
        with self._lock:
            self._keys[key.id] = key
        return key

    def find(self, key_id: uuid.UUID) -> StoredKey | None:
        with self._lock:
            return self._keys.get(key_id)

    def sign(self, key: StoredKey, message: str) -> EcdsaSignature:
        return signer.sign(key.shares, key.threshold, hash_message(message))

    def verify(self, key: StoredKey, message: str, signature: EcdsaSignature) -> bool:
        return signer.verify(key.shares[0].public_key, hash_message(message), signature)
