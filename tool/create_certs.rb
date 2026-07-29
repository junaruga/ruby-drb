#!/usr/bin/env ruby
# frozen_string_literal: true

# This script creates RSA and ML-DSA-65 SSL/TLS test certificates.
# It requires OpenSSL >= 3.5 for ML-DSA-65 support.

require 'fileutils'
require 'openssl'

FIXTURES_DIR = File.join(__dir__, '..', 'test', 'drb', 'fixtures')
# Define certificate validity period for testing.
NOT_BEFORE = Time.utc(2009, 1, 1)
NOT_AFTER  = Time.utc(2049, 12, 31, 23, 59, 59)

# Generate a private key for the given algorithm.
def create_key(algorithm)
  case algorithm
  when 'RSA'
    OpenSSL::PKey::RSA.new(2048)
  when 'ML-DSA-65'
    OpenSSL::PKey.generate_key(algorithm)
  else
    raise(ArgumentError, "#{algorithm} algorithm not supported.")
  end
end

# Return the digest algorithm for certificate signing.
def digest(algorithm)
  case algorithm
  when 'RSA'
    'SHA256'
  when 'ML-DSA-65'
    # ML-DSA has a built-in digest and does not accept one.
    nil
  else
    raise(ArgumentError, "#{algorithm} algorithm not supported.")
  end
end

# Create a certificate.
# https://ruby.github.io/openssl/OpenSSL/X509/Certificate.html
def create_cert(key:, subject:, serial:, algorithm:, extensions:,
                issuer_key: key, issuer_cert: nil)
  cert = OpenSSL::X509::Certificate.new
  # Set 2 to create a version 3 (v3) certificate to use additional extension
  # fields (RFC 5280 Section 3.1, 4.1.2.1)
  # https://www.rfc-editor.org/info/rfc5280/#section-3.1
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.1
  cert.version = 2
  # Set unique positive integer serial number for each certificate (RFC 5280
  # Section 4.1.2.2)
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.2
  cert.serial = serial
  # Set subject (RFC 5280 Section 4.1.2.6)
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.6
  cert.subject = OpenSSL::X509::Name.new(subject)
  # Set issuer (RFC 5280 Section 4.1.2.4)
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.4
  cert.issuer = issuer_cert ? issuer_cert.subject : cert.subject
  # Set public key used for certificate
  cert.public_key = OpenSSL::PKey.read(key.public_to_pem)
  # Set validity period (RFC 5280 Section 4.1.2.5)
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.5
  cert.not_before = NOT_BEFORE
  cert.not_after = NOT_AFTER
  # Set extensions (RFC 5280 Section 4.1.2.9)
  # https://www.rfc-editor.org/info/rfc5280/#section-4.1.2.9
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = issuer_cert || cert
  extensions.each do |ext|
    cert.add_extension(ef.create_extension(*ext))
  end

  cert.sign(issuer_key, digest(algorithm))
  cert
end

# Create CA, server, and client certificates, and write them to fixtures.
# algorithm: algorithm to create key and cert
# prefix: filename prefix for the fixture files
def create_certs(algorithm, prefix)
  subject_base = [%w[C JP], %w[ST Tokyo], %w[O DRbTest]]
  extensions_base = [['subjectKeyIdentifier', 'hash', false]]

  # CA
  ca_key = create_key(algorithm)
  ca_cert = create_cert(
    key: ca_key,
    subject: subject_base + [%w[CN CA]],
    serial: 0,
    algorithm: algorithm,
    extensions: extensions_base + [
      ['basicConstraints', 'CA:TRUE', true],
      ['keyUsage', 'keyCertSign, cRLSign', true],
      ['authorityKeyIdentifier', 'keyid:always', false]
    ]
  )

  # Server
  server_key = create_key(algorithm)
  server_cert = create_cert(
    key: server_key,
    subject: subject_base + [%w[CN localhost]],
    serial: 1,
    algorithm: algorithm,
    extensions: extensions_base + [
      ['keyUsage', 'digitalSignature', true]
    ],
    issuer_key: ca_key,
    issuer_cert: ca_cert
  )

  # Client
  client_key = create_key(algorithm)
  client_cert = create_cert(
    key: client_key,
    subject: subject_base + [%w[CN Client]],
    serial: 2,
    algorithm: algorithm,
    extensions: extensions_base + [
      ['keyUsage', 'digitalSignature', true]
    ],
    issuer_key: ca_key,
    issuer_cert: ca_cert
  )

  # Write fixtures
  {
    'ca.crt' => ca_cert.to_pem,
    'server.crt' => server_cert.to_pem,
    'server.key' => server_key.private_to_pem,
    'client.crt' => client_cert.to_pem,
    'client.key' => client_key.private_to_pem
  }.each do |name, content|
    File.write(File.join(FIXTURES_DIR, "#{prefix}_#{name}"), content)
  end
end

# RSA
create_certs('RSA', 'rsa')

# ML-DSA-65
create_certs('ML-DSA-65', 'mldsa65')
