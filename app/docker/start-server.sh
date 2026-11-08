#!/bin/sh
# Starts sigmadesk-server with the RustDesk ID server's public key, which hbbs writes into the
# shared /keys folder the first time it runs (wait up to 30 s for it).
i=0
while [ ! -s /keys/id_ed25519.pub ] && [ $i -lt 30 ]; do
  sleep 1
  i=$((i + 1))
done
KEY=$(cat /keys/id_ed25519.pub 2>/dev/null || true)
exec /usr/local/bin/sigmadesk-server \
  --port 21180 \
  --data /data/sigmadesk-server.json \
  --download-dir /downloads \
  --rustdesk-host "${PUBLIC_HOST:-localhost}" \
  --rustdesk-key "$KEY"
