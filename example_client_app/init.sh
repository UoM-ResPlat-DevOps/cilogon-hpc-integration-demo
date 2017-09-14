#!/usr/bin/env bash
# Get TLS certificate -- might prompt you whether to re-use or create new if already exists.
./get_host_cert.sh $EMAIL $CLIENT_URL $CLIENT_URL_SECONDARY

# Create database
cd /srv/app
python -c "from app import db;db.create_all()"

