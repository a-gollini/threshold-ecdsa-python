# threshold-ecdsa-python

[![CI](https://github.com/a-gollini/threshold-ecdsa-python/actions/workflows/ci.yml/badge.svg)](https://github.com/a-gollini/threshold-ecdsa-python/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Educational implementation of **threshold ECDSA on secp256k1** in Python, built from public literature only. The core is pure Python (no crypto dependencies): curve arithmetic, secret sharing, DKG and signing are all written from scratch.

This is a port of [threshold-ecdsa-dotnet](https://github.com/a-gollini/threshold-ecdsa-dotnet): same protocol, same structure, same tests.

> ⚠️ **Not for production use.** This is a learning project: scalar multiplication is not constant time, there is no side-channel hardening, and the protocol is not audited.

## Goal

Generate an ECDSA key that is split across `n` parties so that any `t` of them can sign, and no single party ever holds the full private key.

## How it works

**Secret sharing.** A secret `x` is the constant term of a random polynomial `f` of degree `t-1` over the secp256k1 scalar field. Party `i` holds `f(i)`. Any `t` shares reconstruct `x` by Lagrange interpolation at 0; fewer reveal nothing. With Feldman VSS the dealer also publishes `a_j * G` for every coefficient, so each party can check its share: `f(i) * G == sum_j i^j * (a_j * G)`.

**Key generation (DKG).** Every party acts as a dealer for a random value and sends a verified sub-share to everyone else. Party `i` adds the sub-shares it received to get its key share; the public key is the sum of all dealers' `a_0 * G`. The private key is the sum of all dealt values, and nobody ever sees it.

**Threshold signing.** ECDSA needs `s = k^-1 (m + r x)`, and the inverse is the hard part to compute without reconstructing `k`:

```
parties ──DKG──▶ shares of nonce k        parties ──DKG──▶ shares of blinding w
                    │                                           │
                    ├── R = k*G opened  ──▶ r = R.x mod n       │
                    │                                           │
                    └─ open k*w  (interpolate k_i * w_i, degree 2t-2)
                          k*w reveals nothing: w is uniform and secret
                          shares of k^-1 = w_i * (k*w)^-1

each party i:  s_i = (k^-1)_i * (m + r * x_i)      ← a share of s, degree 2t-2
interpolate 2t-1 values s_i  ──▶  s  (normalised to low-s)
```

The result `(r, s)` is a plain ECDSA signature: any verifier needs only the public key. Because the products have degree `2t-2`, signing needs `2t-1` online parties, not `t`. The tests check signatures both with the in-repo verifier and with the `cryptography` library as an independent ECDSA implementation.

**Layout.**

```
src/threshold_ecdsa/
  curve.py     secp256k1 points and scalar helpers
  shamir.py    Shamir + Feldman VSS
  dkg.py       Joint-Feldman distributed key generation
  signer.py    threshold signing and standard ECDSA verification
  api/         FastAPI app + KeyService (application layer)
tests/         pytest: unit tests for the core, integration tests for the API
```

## Usage

```python
import hashlib
from threshold_ecdsa import run_dkg, sign, verify

keys = run_dkg(threshold=2, parties=3)
digest = hashlib.sha256(b"pay 1 BTC to alice").digest()

signature = sign(keys, threshold=2, message_hash=digest)   # needs 2t-1 = 3 signers
assert verify(keys[0].public_key, digest, signature)
```

## REST API

```
pip install -e ".[api]"
uvicorn threshold_ecdsa.api.app:app
```

| Method | Route | Description |
|---|---|---|
| POST | `/keys` | `{ "threshold": 2, "parties": 3 }` runs the DKG; `parties` must be at least `2*threshold-1` |
| GET | `/keys/{id}` | Public information (compressed public key) |
| POST | `/keys/{id}/sign` | `{ "message": "..." }` signs SHA-256(message), returns `r`, `s` (hex) |
| POST | `/keys/{id}/verify` | `{ "message", "r", "s" }` verifies with standard ECDSA |

Interactive docs are served at `/docs`. Key shares are held in memory only and are never returned by the API.

## Known limitations

- Everything runs in one process; there is no networking, authentication or persistence.
- Joint-Feldman DKG lets a rushing adversary bias the public key distribution (see Gennaro et al., *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems*).
- Signing needs 2t-1 online parties and assumes honest-but-curious participants: partial signatures are not proven correct.
- Nonce and blinding values are generated per signature with a fresh DKG; no zero-knowledge proofs, no identifiable abort.
- Pure-Python big-integer arithmetic is slow and not constant time.

## Build & test

```
pip install -e ".[dev]"
pytest
```

## Roadmap

- [x] Port of the .NET design to Python
- [x] Port to Rust: [threshold-ecdsa-rust](https://github.com/a-gollini/threshold-ecdsa-rust)

## References

- Shamir, *How to Share a Secret* (1979)
- Feldman, *A Practical Scheme for Non-interactive Verifiable Secret Sharing* (1987)
- Gennaro, Goldfeder, *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (GG18/GG20)

## License

[MIT](LICENSE)
