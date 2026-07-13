#!/bin/bash
set -euo pipefail

IDENTITY=${PRIVATE_NETWORK_LOCAL_SIGNING_IDENTITY:-Private Network Local Development}
ROOT_NAME="${IDENTITY} Root"
LOGIN_KEYCHAIN=${HOME}/Library/Keychains/login.keychain-db

if [[ $(uname -s) != Darwin ]]; then
  echo "local macOS signing setup must run on macOS" >&2
  exit 69
fi

if /usr/bin/security find-identity -v -p codesigning "$LOGIN_KEYCHAIN" | /usr/bin/grep -Fq "\"$IDENTITY\""; then
  printf 'Local code-signing identity is already available: %s\n' "$IDENTITY"
  exit 0
fi

OPENSSL=$(command -v openssl || true)
if [[ -z "$OPENSSL" ]]; then
  echo "openssl is required to create the local signing identity" >&2
  exit 69
fi

WORK=$(mktemp -d)
trap '/bin/rm -rf "$WORK"' EXIT INT TERM
umask 077

"$OPENSSL" req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
  -subj "/CN=$ROOT_NAME" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$WORK/root.key" \
  -out "$WORK/root.crt"

"$OPENSSL" req -newkey rsa:3072 -nodes -sha256 \
  -subj "/CN=$IDENTITY" \
  -keyout "$WORK/signing.key" \
  -out "$WORK/signing.csr"

printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=critical,codeSigning' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid,issuer' \
  > "$WORK/signing.ext"

"$OPENSSL" x509 -req -sha256 -days 3650 \
  -in "$WORK/signing.csr" \
  -CA "$WORK/root.crt" \
  -CAkey "$WORK/root.key" \
  -CAcreateserial \
  -extfile "$WORK/signing.ext" \
  -out "$WORK/signing.crt"

P12_PASSWORD=$("$OPENSSL" rand -hex 24)
"$OPENSSL" pkcs12 -legacy -export \
  -name "$IDENTITY" \
  -inkey "$WORK/signing.key" \
  -in "$WORK/signing.crt" \
  -certfile "$WORK/root.crt" \
  -passout "pass:$P12_PASSWORD" \
  -out "$WORK/signing.p12"

# Trust only this local root for code signing, then import the leaf and private key.
/usr/bin/security add-trusted-cert -r trustRoot -p codeSign \
  -k "$LOGIN_KEYCHAIN" "$WORK/root.crt"
/usr/bin/security import "$WORK/signing.p12" \
  -k "$LOGIN_KEYCHAIN" \
  -P "$P12_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security >/dev/null

if ! /usr/bin/security find-identity -v -p codesigning "$LOGIN_KEYCHAIN" | /usr/bin/grep -Fq "\"$IDENTITY\""; then
  echo "the local certificate was imported but is not a valid code-signing identity" >&2
  exit 78
fi

printf 'Installed local code-signing identity: %s\n' "$IDENTITY"
printf 'Its private key remains in: %s\n' "$LOGIN_KEYCHAIN"
