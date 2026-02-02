#!/usr/bin/env bash
set -e

CERT_DIR="/usr/share/elasticsearch/config/certs"
mkdir -p "$CERT_DIR"

# generate certs if missing
if [ ! -f "$CERT_DIR/transport.p12" ] || [ ! -f "$CERT_DIR/http.p12" ]; then
  echo "[entrypoint] certs missing -> generating..."

  # CA
  if [ ! -f "$CERT_DIR/elastic-stack-ca.p12" ]; then
    /usr/share/elasticsearch/bin/elasticsearch-certutil ca --silent \
      --out "$CERT_DIR/elastic-stack-ca.p12" --pass ""
  fi

  # transport
  /usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent \
    --ca "$CERT_DIR/elastic-stack-ca.p12" --ca-pass "" \
    --out "$CERT_DIR/transport.p12" --pass "" \
    --name es01 --dns elasticsearch --dns localhost --ip 127.0.0.1

  # http
  /usr/share/elasticsearch/bin/elasticsearch-certutil cert --silent \
    --ca "$CERT_DIR/elastic-stack-ca.p12" --ca-pass "" \
    --out "$CERT_DIR/http.p12" --pass "" \
    --name es01 --dns elasticsearch --dns localhost --ip 127.0.0.1

  echo "[entrypoint] certs generated OK"
fi

exec /usr/local/bin/docker-entrypoint.sh
