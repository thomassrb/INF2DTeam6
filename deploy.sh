#!/usr/bin/env bash
set -euo pipefail

echo "Starting MobyPark deployment..."

SRC_DIR="${GITHUB_WORKSPACE:-$(pwd)}"
TARGET_DIR="/home/ubuntu-1056396/mobypark"

echo "Source: $SRC_DIR"
echo "Target: $TARGET_DIR"

mkdir -p "$TARGET_DIR"

# Copy code, but keep venv/logs on the server
rsync -a --delete \
  --exclude '.git' \
  --exclude 'venv' \
  --exclude 'pycache' \
  --exclude 'logs' \
  --exclude 'start_app.sh' \
  "$SRC_DIR"/ "$TARGET_DIR"/

echo "Activating virtual environment..."
source "$TARGET_DIR/venv/bin/activate"

echo "Installing dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r "$TARGET_DIR/requirements.txt"

echo "Stopping any existing server..."
pkill -f "uvicorn MobyPark.api.app:app" || true

echo "Starting server in background..."
nohup uvicorn api.app:app --host 0.0.0.0 --port 8000 > "$TARGET_DIR/server.log" 2>&1 &

echo "Deployment completed successfully!"