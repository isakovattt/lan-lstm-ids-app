#!/bin/zsh
cd "$(dirname "$0")"
source .venv/bin/activate
export IDS_SERVER_URL="http://127.0.0.1:5050/analyze"
python agent_client.py
