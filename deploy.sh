#!/bin/bash
set -e

# Config
SERVER_IP="145.24.223.87"
SERVER_USER="ubuntu-1056396"
APP_NAME="mobypark"
DOMAIN="145.24.223.87"

# paths voor de deployment
DEPLOY_DIR="/var/www/$APP_NAME"
CURRENT_LINK="$DEPLOY_DIR/current"
NEW_DEPLOY_DIR="$DEPLOY_DIR/$(date +%Y%m%d%H%M%S)"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"

# als deployment directory niet bestaat een maken
echo "Creating deployment directory on server..."
ssh $SERVER_USER@$SERVER_IP "mkdir -p $NEW_DEPLOY_DIR"

# nieuwe versie copieren naar server
echo "Copying files to server..."
rsync -avz -e "ssh -o StrictHostKeyChecking=no" \
    --exclude '.git' \
    --exclude '.github' \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '.env' \
    ./ $SERVER_USER@$SERVER_IP:$NEW_DEPLOY_DIR/

ssh user@your-server-ip "
    cd $NEW_DEPLOY_DIR && \
    python3 -m venv venv && \
    source venv/bin/activate && \
    pip install --upgrade pip && \
    if [ -f requirements.txt ]; then pip install -r requirements.txt; fi && \
    pip install uvicorn gunicorn && \
    deactivate
"

cat > $APP_NAME.nginx.conf <<EOL
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Optional: Add static file serving if needed
    # location /static/ {
    #     alias $NEW_DEPLOY_DIR/static/;
    #     expires 30d;
    # }
}
EOL

scp -o StrictHostKeyChecking=no $APP_NAME.nginx.conf $SERVER_USER@$SERVER_IP:$NEW_DEPLOY_DIR/
rm $APP_NAME.nginx.conf

ssh user@your-server-ip "
    # Stop the current service if running
    sudo systemctl stop $APP_NAME.service 2>/dev/null || true
    
    # Update the current symlink to point to the new version
    ln -sfn $NEW_DEPLOY_DIR $CURRENT_LINK
    
    # Update Nginx configuration
    sudo cp $NEW_DEPLOY_DIR/$APP_NAME.nginx.conf $NGINX_SITES_AVAILABLE/$APP_NAME
    sudo ln -sf $NGINX_SITES_AVAILABLE/$APP_NAME $NGINX_SITES_ENABLED/
    
    # Create systemd service file
    cat > /tmp/$APP_NAME.service <<EOL
[Unit]
Description=$APP_NAME Service
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=$CURRENT_LINK
Environment="PATH=$CURRENT_LINK/venv/bin"
ExecStart=$CURRENT_LINK/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker MobyPark.api.app:app --bind 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Install and start the service
    sudo mv /tmp/$APP_NAME.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable $APP_NAME.service
    sudo systemctl start $APP_NAME.service
    
    # Test Nginx configuration and reload
    sudo nginx -t
    sudo systemctl reload nginx
"

echo "Deployment completed successfully!"
echo "New version is now live at $NEW_DEPLOY_DIR"
