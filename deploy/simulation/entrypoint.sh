#!/bin/sh
set -eu
umask 077
case "${1:-}" in a|b) role="$1" ;; *) exit 2 ;; esac
if [ ! -f /data/config.yaml ]; then cp "/configs/$role.yaml" /data/config.yaml; fi
if [ ! -f /data/bootstrap.json ]; then
  "fleetops-$role" init --config /data/config.yaml > /data/bootstrap.tmp
  mv /data/bootstrap.tmp /data/bootstrap.json
fi
exec "fleetops-$role" serve --config /data/config.yaml
