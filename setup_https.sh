#!/bin/bash
# Tempris HTTPS Setup Script
# Run with: sudo bash /home/tempris/setup_https.sh

set -e

echo "=== Tempris HTTPS Setup ==="

# 1. Copy SSL config to nginx
cp /home/tempris/nginx_tempris_ssl.conf /etc/nginx/sites-available/tempris_ssl
echo "[✓] SSL config copied"

# 2. Replace default site with SSL config
ln -sf /etc/nginx/sites-available/tempris_ssl /etc/nginx/sites-enabled/default
echo "[✓] Site enabled"

# 3. Test nginx configuration
nginx -t
echo "[✓] Nginx config test passed"

# 4. Reload nginx
systemctl reload nginx
echo "[✓] Nginx reloaded"

# 5. Verify
echo ""
echo "=== Verification ==="
curl -sk https://127.0.0.1/api/health
echo ""
echo ""
echo "=== HTTPS is now active at https://187.127.114.218 ==="
echo "Note: Browser will show a security warning (self-signed cert)."
echo "Click 'Advanced' → 'Proceed' to access the platform."
