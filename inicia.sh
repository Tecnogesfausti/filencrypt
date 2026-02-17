#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "Error: no existe .venv en $SCRIPT_DIR"
  exit 1
fi

read -r -s -p "Introduce LISTA_PASSWORD: " LISTA_PASSWORD_INPUT
echo

if [[ -z "$LISTA_PASSWORD_INPUT" ]]; then
  echo "Error: la contrasena no puede estar vacia."
  exit 1
fi

export LISTA_PASSWORD="$LISTA_PASSWORD_INPUT"
unset LISTA_PASSWORD_INPUT

source .venv/bin/activate

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
ALGOD_ADDRESS="${ALGOD_ADDRESS:-https://mainnet-api.algonode.cloud}"
API_RATE_LIMIT_PER_MIN="${API_RATE_LIMIT_PER_MIN:-120}"
BALANCE_CACHE_TTL_SECONDS="${BALANCE_CACHE_TTL_SECONDS:-180}"

export ALGOD_ADDRESS API_RATE_LIMIT_PER_MIN BALANCE_CACHE_TTL_SECONDS

exec uvicorn webserver:app --host "$HOST" --port "$PORT"
