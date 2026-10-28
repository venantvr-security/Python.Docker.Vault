#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs
openssl genpkey -algorithm Ed25519 -out certs/client_id.key
openssl pkey -in certs/client_id.key -pubout -out certs/client_id.pub
# Compose (hors swarm) bind-monte le fichier avec les droits de l'hôte :
# l'utilisateur du conteneur (uid 10001) doit pouvoir le lire (lab uniquement).
chmod 644 certs/client_id.key certs/client_id.pub

echo "=== Test Standalone (Debug sans Docker) ==="
python3 standalone_debug.py

echo -e "\n=== Lancement Docker BuildKit ==="
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1
docker compose up --build --abort-on-container-exit
