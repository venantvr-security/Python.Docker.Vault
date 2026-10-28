import os
import time
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

app = FastAPI()

# Stockage en mémoire (Secrets & Cache anti-rejeu)
SECRETS_DB = {"db_pass": b"SuperSecret_Postgres_2026!"}
SEEN_NONCES: set[str] = set()
MAX_CLOCK_SKEW = 5  # secondes

# Chargement de la clé publique d'identité du client autorisé
PUB_KEY_PATH = os.getenv("CLIENT_PUB_KEY_PATH", "/var/secrets/client_id.pub")
with open(PUB_KEY_PATH, "rb") as f:
    AUTHORIZED_CLIENT_PUB = serialization.load_pem_public_key(f.read())


class SecretRequest(BaseModel):
    ephemeral_pub: str
    timestamp: int
    nonce: str
    secret_name: str
    signature: str


@app.post("/v1/secret")
def get_secret(req: SecretRequest):
    now = int(time.time())
    if abs(now - req.timestamp) > MAX_CLOCK_SKEW:
        raise HTTPException(status_code=403, detail="Timestamp hors tolérance (Replay ?)")
    if req.nonce in SEEN_NONCES:
        raise HTTPException(status_code=403, detail="Nonce déjà utilisé")

    # Reconstruction déterministe du payload signé
    payload_bytes = json.dumps({
        "ephemeral_pub": req.ephemeral_pub,
        "timestamp": req.timestamp,
        "nonce": req.nonce,
        "secret_name": req.secret_name
    }, sort_keys=True).encode()

    # 1. Authentification par vérification de la signature Ed25519
    try:
        AUTHORIZED_CLIENT_PUB.verify(bytes.fromhex(req.signature), payload_bytes)
    except (InvalidSignature, ValueError):
        raise HTTPException(status_code=401, detail="Signature d'identité invalide")

    SEEN_NONCES.add(req.nonce)

    if req.secret_name not in SECRETS_DB:
        raise HTTPException(status_code=404, detail="Secret introuvable")

    # 2. Forward Secrecy : Échange X25519 éphémère (ECIES)
    try:
        client_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(req.ephemeral_pub))
    except ValueError:
        raise HTTPException(status_code=400, detail="Clé éphémère invalide")
    vault_eph_priv = x25519.X25519PrivateKey.generate()
    shared_key = vault_eph_priv.exchange(client_eph_pub)

    # Dérivation HKDF + Chiffrement ChaCha20-Poly1305
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vault-ecies-v1"
    ).derive(shared_key)

    aead_nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(derived_key).encrypt(aead_nonce, SECRETS_DB[req.secret_name], None)

    return {
        "vault_ephemeral_pub": vault_eph_priv.public_key().public_bytes_raw().hex(),
        "aead_nonce": aead_nonce.hex(),
        "ciphertext": ciphertext.hex()
    }
