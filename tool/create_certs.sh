#!/bin/sh

# This script creates RSA and ML-DSA-65 SSL/TLS test certificates.
# It requires OpenSSL >= 3.5 for ML-DSA-65 support.

set -eu

TOP_DIR="$(git rev-parse --show-toplevel)"
FIXTURES_DIR="${TOP_DIR}/test/drb/fixtures"
TMP_DIR="${TOP_DIR}/tmp/create_certs"

create_certs() {
  genpkey_args="${1}"
  prefix="${2}"

  # CA
  mkdir -p "${TMP_DIR}/${prefix}"
  openssl genpkey ${genpkey_args} -out "${TMP_DIR}/${prefix}/ca.key"
  openssl req -x509 \
    -key "${TMP_DIR}/${prefix}/ca.key" \
    -subj "/C=JP/ST=Tokyo/O=DRbTest/CN=CA" \
    -not_before 090101000000Z -not_after 491231235959Z \
    -out "${TMP_DIR}/${prefix}/ca.crt"

  # Server
  openssl genpkey ${genpkey_args} -out "${TMP_DIR}/${prefix}/server.key"
  openssl req -new \
    -key "${TMP_DIR}/${prefix}/server.key" \
    -subj "/C=JP/ST=Tokyo/O=DRbTest/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -out "${TMP_DIR}/${prefix}/server.csr"
  openssl x509 -req \
    -in "${TMP_DIR}/${prefix}/server.csr" \
    -CA "${TMP_DIR}/${prefix}/ca.crt" \
    -CAkey "${TMP_DIR}/${prefix}/ca.key" \
    -set_serial 1 \
    -copy_extensions copyall \
    -not_before 090101000000Z -not_after 491231235959Z \
    -out "${TMP_DIR}/${prefix}/server.crt"

  # Client
  openssl genpkey ${genpkey_args} -out "${TMP_DIR}/${prefix}/client.key"
  openssl req -new \
    -key "${TMP_DIR}/${prefix}/client.key" \
    -subj "/C=JP/ST=Tokyo/O=DRbTest/CN=Client" \
    -out "${TMP_DIR}/${prefix}/client.csr"
  openssl x509 -req \
    -in "${TMP_DIR}/${prefix}/client.csr" \
    -CA "${TMP_DIR}/${prefix}/ca.crt" \
    -CAkey "${TMP_DIR}/${prefix}/ca.key" \
    -set_serial 2 \
    -not_before 090101000000Z -not_after 491231235959Z \
    -out "${TMP_DIR}/${prefix}/client.crt"

  cp "${TMP_DIR}/${prefix}/ca.crt" "${FIXTURES_DIR}/${prefix}_ca.crt"
  cp "${TMP_DIR}/${prefix}/server.crt" "${FIXTURES_DIR}/${prefix}_server.crt"
  cp "${TMP_DIR}/${prefix}/server.key" "${FIXTURES_DIR}/${prefix}_server.key"
  cp "${TMP_DIR}/${prefix}/client.crt" "${FIXTURES_DIR}/${prefix}_client.crt"
  cp "${TMP_DIR}/${prefix}/client.key" "${FIXTURES_DIR}/${prefix}_client.key"
}

rm -rf "${TMP_DIR}"

# RSA
create_certs "-algorithm rsa -pkeyopt rsa_keygen_bits:2048" "rsa"

# ML-DSA-65
create_certs "-algorithm mldsa65" "mldsa65"
