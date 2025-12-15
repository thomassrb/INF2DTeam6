#!/bin/bash
set -e

echo "Starting MobyPark deployment..."

SERVER_IP="145.24.223.87"
SERVER_USER="ubuntu-1056396"
APP_NAME="mobypark"
REMOTE_DIR="/var/www/$APP_NAME"
TIMESTAMP=$(date +%Y%m%d%H%M%S)
DEPLOY_DIR="$REMOTE_DIR/releases/$TIMESTAMP"
CURRENT_LINK="$REMOTE_DIR/current"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

section() {
    echo -e "\n${BLUE}==>${NC} ${GREEN}$1${NC}"
}

check_ssh() {
    section "🔑 Checking SSH access"
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 $SERVER_USER@$SERVER_IP echo "SSH connection successful" > /dev/null 2>&1; then
        echo "SSH connection to $SERVER_USER@$SERVER_IP failed"
        echo "Please ensure:"
        echo "1. Your SSH key is added to ~/.ssh/authorized_keys on the server"
        echo "2. The server's IP and username are correct"
        echo "3. The server is accessible from your network"
        exit 1
    fi
    echo "SSH connection successful"
}
  cd ~/mobypark-current
  
  if [ -f deploy.sh ]; then
    echo 'Running deploy.sh...'
    chmod +x deploy.sh
    ./deploy.sh
  else
    echo 'No deploy.sh found in the repository root!'
    ls -la
    exit 1
  fi
  
  echo 'Cleaning up old deployments...'
  ls -dt ~/mobypark-* 2>/dev/null | tail -n +6 | xargs -r rm -rf
"

echo "Deployment completed successfully!"