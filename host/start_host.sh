#!/bin/bash

# Get domain name used for certs (won't work if you've got several setup!)
HOST=$(ls /etc/letsencrypt/live/)

# Symlink certificates so available to gsissh and restrict permissions to keep it happy
ln -sf /etc/letsencrypt/live/$HOST/cert.pem /etc/grid-security/hostcert.pem
ln -sf /etc/letsencrypt/live/$HOST/privkey.pem /etc/grid-security/hostkey.pem
chmod 600 /etc/grid-security/*.pem

# Start gsisshd
/sbin/gsisshd -D