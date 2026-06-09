#!/bin/zsh
cd "$(dirname "$0")"
source .venv/bin/activate
export IDS_SERVER_PORT=5050
export IDS_DATABASE_URL="${IDS_DATABASE_URL:-postgresql://ids_user:ids_password@127.0.0.1:5432/ids_db}"
python server.py
