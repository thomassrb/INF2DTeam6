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

echo "Deployment completed successfully!"