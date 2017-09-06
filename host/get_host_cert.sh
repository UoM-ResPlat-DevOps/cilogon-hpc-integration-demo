#!/bin/bash

display_usage() {
	echo "Usage: ./get_host_cert.sh [Email] [Host URL 1] [Host URL 2 (optional)]"
}

if [  $# -le 1 ]
then
    display_usage
    exit 1
fi

EMAIL=$1
HOST_1=$2
HOST_2=$3

if [ -z "$HOST_2" ]
then
    /letsencrypt/letsencrypt-auto --debug certonly --standalone --email $EMAIL -d $HOST_1 --no-eff-email --agree-tos
else
    /letsencrypt/letsencrypt-auto --debug certonly --standalone --email $EMAIL -d $HOST_1 -d $HOST_2 --no-eff-email --agree-tos
fi
