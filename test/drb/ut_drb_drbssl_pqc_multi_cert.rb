# frozen_string_literal: false

# drbssl server with PQC-supported key exchange ML-KEM (X25519MLKEM768), and
# pre-generated ML-DSA-65 (PQC) and RSA (non-PQC) dual (multiple) server
# certificates with client certificate verification.

require_relative 'ut_drb'
require_relative 'drbtest_utils'
require 'drb/ssl'

if __FILE__ == $0
  def ARGV.shift
    it = super()
    raise "usage: #{$0} <manager-uri> <name>" unless it
    it
  end

  config = Hash.new
  # This config is used for both server and client connections.
  # As a server: verify and require the client to present a certificate signed
  # by a trusted CA.
  # As a client: verify the manager's pre-generated server certificate via the
  # CA store (SSLCertificateStore).
  config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_PEER |
                           OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
  config[:SSLCertificates] = [
    [
      OpenSSL::X509::Certificate.new(
        DRbTests::Fixtures.read_file('mldsa65_server.crt')),
      OpenSSL::PKey.read(
        DRbTests::Fixtures.read_file('mldsa65_server.key'))
    ],
    [
      OpenSSL::X509::Certificate.new(
        DRbTests::Fixtures.read_file('rsa_server.crt')),
      OpenSSL::PKey::RSA.new(
        DRbTests::Fixtures.read_file('rsa_server.key'))
    ]
  ]
  # Specify key exchange group.
  config[:SSLGroups] = 'X25519MLKEM768'
  # Specify signature algorithms.
  config[:SSLSignatureAlgorithms] = 'mldsa65:rsa_pss_rsae_sha256'
  # CA certificates to verify peer's certificate.
  # As a server: verify the client's certificate.
  # As a client: verify the manager's server certificate.
  store = OpenSSL::X509::Store.new
  store.add_cert(OpenSSL::X509::Certificate.new(
    DRbTests::Fixtures.read_file('mldsa65_ca.crt')))
  store.add_cert(OpenSSL::X509::Certificate.new(
    DRbTests::Fixtures.read_file('rsa_ca.crt')))
  config[:SSLCertificateStore] = store
  # CA certificate(s) sent to the client indicating which certificates the
  # server accepts. Helps the client choose which certificate to present.
  config[:SSLClientCA] = [
    OpenSSL::X509::Certificate.new(
      DRbTests::Fixtures.read_file('mldsa65_ca.crt')),
    OpenSSL::X509::Certificate.new(
      DRbTests::Fixtures.read_file('rsa_ca.crt'))
  ]

  DRb.start_service('drbssl://localhost:0', DRbTests::DRbEx.new, config)
  es = DRb::ExtServ.new(ARGV.shift, ARGV.shift)
  DRb.thread.join
  es.stop_service if es.alive?
end
