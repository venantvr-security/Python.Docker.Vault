# Lab Zero-Trust Vault

Mini-Vault FastAPI : authentification Ed25519, anti-rejeu (timestamp + nonce), échange X25519 éphémère (ECIES) avec HKDF-SHA256 et ChaCha20-Poly1305.

## Architecture

```mermaid
flowchart LR
    subgraph net[zero-trust-net - réseau interne]
        C[client-app<br/>client.py]
        V[mini-vault<br/>vault.py :8000]
    end
    S1[(secret client_id.key)] -.tmpfs /var/secrets.-> C
    S2[(secret client_id.pub)] -.tmpfs /var/secrets.-> V
    C -- "POST /v1/secret<br/>payload signé Ed25519" --> V
    V -- "clé pub éphémère + nonce AEAD + ciphertext" --> C
```

## Protocole

```mermaid
sequenceDiagram
    participant C as Client
    participant V as Vault
    C->>C: Génère paire X25519 éphémère
    C->>C: Signe {ephemeral_pub, timestamp, nonce, secret_name} (Ed25519)
    C->>V: POST /v1/secret
    V->>V: Vérifie |now - timestamp| ≤ 5 s
    V->>V: Rejette si nonce déjà vu
    V->>V: Vérifie la signature (clé publique autorisée)
    V->>V: Génère paire X25519 éphémère, ECDH, HKDF
    V->>V: Chiffre le secret (ChaCha20-Poly1305)
    V-->>C: vault_ephemeral_pub, aead_nonce, ciphertext
    C->>C: ECDH, HKDF, déchiffre en RAM
```

## Utilisation

- Tout-en-un : `./setup.sh` (génère les clés, test local, puis Docker BuildKit)
- Local sans Docker : `python3 standalone_debug.py`
- Deux terminaux (breakpoints IDE) :
  - `CLIENT_PUB_KEY_PATH=./certs/client_id.pub uvicorn vault:app --host 127.0.0.1 --port 8000 --reload`
  - `CLIENT_PRIV_KEY_PATH=./certs/client_id.key VAULT_URL=http://127.0.0.1:8000/v1/secret python3 client.py`

Lab uniquement : secrets et nonces en mémoire, clés en `chmod 644`.
