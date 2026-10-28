import os
import time
import json
import httpx
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PRIV_KEY_PATH = os.getenv("CLIENT_PRIV_KEY_PATH", "/var/secrets/client_id.key")
VAULT_URL = os.getenv("VAULT_URL", "http://mini-vault:8000/v1/secret")


def load_identity_key():
    with open(PRIV_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def fetch_secret(secret_name: str, id_priv_key, client: httpx.Client | None = None) -> str:
    # 1. Génération de la paire éphémère X25519 en RAM (unique pour cet appel)
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_hex = eph_priv.public_key().public_bytes_raw().hex()

    payload = {
        "ephemeral_pub": eph_pub_hex,
        "timestamp": int(time.time()),
        "nonce": os.urandom(16).hex(),
        "secret_name": secret_name
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode()

    # 2. Signature avec la clé privée d'identité
    signature_hex = id_priv_key.sign(payload_bytes).hex()

    # 3. Appel au Vault
    http = client or httpx
    resp = http.post(VAULT_URL, json={**payload, "signature": signature_hex})
    resp.raise_for_status()
    data = resp.json()

    # 4. Dérivation ECDH et déchiffrement en RAM
    vault_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(data["vault_ephemeral_pub"]))
    shared_key = eph_priv.exchange(vault_eph_pub)

    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"vault-ecies-v1"
    ).derive(shared_key)

    plaintext = ChaCha20Poly1305(derived_key).decrypt(
        bytes.fromhex(data["aead_nonce"]),
        bytes.fromhex(data["ciphertext"]),
        None
    )
    print(f"[CLIENT] Clé publique éphémère utilisée : {eph_pub_hex[:16]}... -> Secret : {plaintext.decode()}")
    return plaintext.decode()


if __name__ == "__main__":
    id_key = load_identity_key()
    for i in range(1, 3):
        print(f"--- Appel #{i} ---")
        fetch_secret("db_pass", id_key)
        time.sleep(1)
