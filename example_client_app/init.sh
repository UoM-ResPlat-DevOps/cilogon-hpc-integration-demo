#!/usr/bin/env bash
# Create self-signed keys for TLS - TODO: replace with Let's Encrypt
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /selfsigned.key -out /selfsigned.crt -subj "/C=AU/ST=A/L=A/O=A/CN=A"

# Create database
cd /srv/app
python -c "from app import db;db.create_all()"
