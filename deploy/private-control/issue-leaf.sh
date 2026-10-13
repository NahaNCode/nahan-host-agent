#!/usr/bin/env bash
set -euo pipefail
umask 077
if (($# != 4)); then
  printf 'Usage: bash issue-leaf.sh ISSUER_CERT ISSUER_KEY PASSPHRASE_FILE NEW_OUTPUT_DIRECTORY\n' >&2
  exit 1
fi
cert=$1
key=$2
pass=$3
out=$4
[[ -f $cert && -f $key && -f $pass && ! -e $out ]] || { printf 'Inputs unavailable or output already exists.\n' >&2; exit 1; }
mkdir -m 0700 -- "$out"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/endpoint.key"
openssl req -new -sha256 -key "$out/endpoint.key" -subj '/O=NahaN/CN=control.nahan.internal' -out "$out/endpoint.csr"
serial=$(openssl rand -hex 16)
openssl x509 -req -in "$out/endpoint.csr" -CA "$cert" -CAkey "$key" \
  -passin "file:$pass" -set_serial "0x$serial" -days 90 -sha256 \
  -extfile "$(dirname "$0")/leaf.ext" -out "$out/endpoint.pem"
openssl verify -partial_chain -CAfile "$cert" -verify_hostname control.nahan.internal "$out/endpoint.pem"
openssl crl2pkcs7 -nocrl -certfile "$out/endpoint.pem" -certfile "$cert" |
  openssl pkcs7 -print_certs -quiet -out "$out/endpoint.chain.pem"
printf 'Leaf issued for 90 days. Deploy only endpoint.key and endpoint.chain.pem; never deploy issuer keys.\n'
