#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -d ".venv" ]]; then
  echo "No existe .venv; creando entorno virtual..."
  python3 -m venv .venv
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

if ! "$SCRIPT_DIR/.venv/bin/python" -m pip --version >/dev/null 2>&1; then
  echo "pip no disponible en .venv; intentando bootstrap con ensurepip..."
  if ! "$SCRIPT_DIR/.venv/bin/python" -m ensurepip --upgrade >/dev/null 2>&1; then
    echo "Error: no se pudo instalar pip en .venv."
    echo "En Debian/Ubuntu instala: sudo apt install python3-venv"
    exit 1
  fi
fi

if [[ -f "requirements.txt" ]]; then
  if ! "$SCRIPT_DIR/.venv/bin/python" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
    echo "Instalando dependencias desde requirements.txt..."
    "$SCRIPT_DIR/.venv/bin/python" -m pip install -U pip
    "$SCRIPT_DIR/.venv/bin/python" -m pip install -r requirements.txt
  fi
else
  echo "Warning: no existe requirements.txt; intentando continuar."
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
ALGOD_ADDRESS="${ALGOD_ADDRESS:-https://mainnet-api.algonode.cloud}"
API_RATE_LIMIT_PER_MIN="${API_RATE_LIMIT_PER_MIN:-120}"
BALANCE_CACHE_TTL_SECONDS="${BALANCE_CACHE_TTL_SECONDS:-180}"

export ALGOD_ADDRESS API_RATE_LIMIT_PER_MIN BALANCE_CACHE_TTL_SECONDS

exec "$SCRIPT_DIR/.venv/bin/python" -m uvicorn webserver:app --host "$HOST" --port "$PORT"
