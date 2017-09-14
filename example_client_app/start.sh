#!/usr/bin/env bash

# Get path to Let's Encrypt certs
HOST=$(ls /etc/letsencrypt/live/)

# Paths to cert and private key
CERT_PATH=/etc/letsencrypt/live/$HOST/cert.pem
KEY_PATH=/etc/letsencrypt/live/$HOST/privkey.pem

cd /srv/app
gunicorn -w 4 -b 0.0.0.0:443 --keyfile $KEY_PATH --certfile $CERT_PATH app:app