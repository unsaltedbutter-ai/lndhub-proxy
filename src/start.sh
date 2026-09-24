#!/bin/bash
# Wrapper so PM2 never captures the secrets in its process env (and therefore
# never writes them to ~/.pm2/dump.pm2, which is group-readable by default).
# The env file is read FRESH at every start/restart — edit /etc/lndhub-proxy/env,
# then `pm2 restart lndhub-proxy` to apply.
set -euo pipefail
set -a; . /etc/lndhub-proxy/env; set +a
cd "$(dirname "$0")/.."
exec node src/server.js
