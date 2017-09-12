#!/usr/bin/env bash
cd /srv/app
gunicorn -w 4 -b 0.0.0.0:4000 --keyfile /selfsigned.key --certfile /selfsigned.crt app:app