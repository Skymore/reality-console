#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 relay.example.com" >&2
  exit 64
fi

server_name=$1
output=${RELAY_PKI_DIR:-pki}

if [ -e "$output" ]; then
  echo "refusing to overwrite existing $output" >&2
  exit 73
fi

umask 077
mkdir -p "$output"

openssl ecparam -name prime256v1 -genkey -noout -out "$output/relay-ca-key.pem"
openssl req -x509 -new -sha256 -key "$output/relay-ca-key.pem" \
  -subj "/CN=Private Network Relay CA" -days 365 \
  -out "$output/relay-ca.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "$output/relay-server-key.pem"
openssl req -new -sha256 -key "$output/relay-server-key.pem" \
  -subj "/CN=$server_name" -out "$output/relay-server.csr"
printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$server_name" \
  > "$output/relay-server.ext"
openssl x509 -req -sha256 -in "$output/relay-server.csr" \
  -CA "$output/relay-ca.pem" -CAkey "$output/relay-ca-key.pem" -CAcreateserial \
  -days 90 -extfile "$output/relay-server.ext" -out "$output/relay-server.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "$output/node-key.pem"
openssl req -new -sha256 -key "$output/node-key.pem" \
  -subj "/CN=Opaque Relay Node" -out "$output/node.csr"
printf 'extendedKeyUsage=clientAuth\n' > "$output/node.ext"
openssl x509 -req -sha256 -in "$output/node.csr" \
  -CA "$output/relay-ca.pem" -CAkey "$output/relay-ca-key.pem" -CAcreateserial \
  -days 30 -extfile "$output/node.ext" -out "$output/node.pem"

openssl rand -hex 32 | tr -d '\n' > "$output/route-token"
chmod 600 "$output/relay-ca-key.pem" "$output/relay-server-key.pem" \
  "$output/node-key.pem" "$output/route-token"
rm -f "$output/relay-server.csr" "$output/relay-server.ext" \
  "$output/node.csr" "$output/node.ext" "$output/relay-ca.srl"

token_hash=$(openssl dgst -sha256 "$output/route-token" | awk '{print $2}')
cert_hash=$(openssl x509 -in "$output/node.pem" -outform DER \
  | openssl dgst -sha256 | awk '{print $2}')

echo "node_token_sha256 = $token_hash"
echo "node_cert_sha256  = $cert_hash"
echo "keep relay-ca-key.pem offline; copy only the files each process needs"
