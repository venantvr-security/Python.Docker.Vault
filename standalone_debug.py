import os
import time
import shutil
import tempfile
import subprocess
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# 1. Création du dossier local temporaire pour les clés d'identité
tmp_dir = tempfile.mkdtemp(prefix="vault_local_")
priv_path = os.path.join(tmp_dir, "client_id.key")
pub_path = os.path.join(tmp_dir, "client_id.pub")

id_priv = ed25519.Ed25519PrivateKey.generate()
with open(priv_path, "wb") as f:
    f.write(id_priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
with open(pub_path, "wb") as f:
    f.write(id_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# 2. Configuration de l'environnement local (sans Docker)
env = os.environ.copy()
env["CLIENT_PRIV_KEY_PATH"] = priv_path
env["CLIENT_PUB_KEY_PATH"] = pub_path
env["VAULT_URL"] = "http://127.0.0.1:8000/v1/secret"

print(f"[LOCAL] Clés générées sur l'hôte dans : {tmp_dir}")
print("[LOCAL] Démarrage du processus Vault (Uvicorn sur 127.0.0.1:8000)...")

# 3. Lancement du Vault comme processus OS natif indépendant
vault_proc = subprocess.Popen(
    ["uvicorn", "vault:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
    env=env
)

try:
    time.sleep(1.5)  # Attente de l'ouverture du socket TCP

    print("[LOCAL] Exécution du Client Python natif :\n")
    subprocess.run(["python3", "client.py"], env=env, check=True)

finally:
    print("\n[LOCAL] Arrêt du Vault et nettoyage des clés...")
    vault_proc.terminate()
    vault_proc.wait()
    shutil.rmtree(tmp_dir, ignore_errors=True)
