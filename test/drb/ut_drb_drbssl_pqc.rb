# frozen_string_literal: false

# drbssl server with PQC-supported key exchange ML-KEM (SecP256r1MLKEM768), and
# auto-generated PQC-supported ML-DSA-65 server certificate.

require_relative 'ut_drb'
require 'drb/ssl'

if __FILE__ == $0
  def ARGV.shift
    it = super()
    raise "usage: #{$0} <manager-uri> <name>" unless it
    it
  end

  config = Hash.new
  # This config is used for both server and client connections.
  # As a server: verify the client's certificate.
  # As a client: verify the manager's self-signed server certificate via
  # SSLVerifyCallback which accepts any certificate.
  config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_PEER
  config[:SSLVerifyCallback] = lambda{ |ok, x509_store|
    true
  }
  # Auto-generate ML-DSA-65 certificate and key.
  config[:SSLCertName] =
    [['C', 'JP'], ['O', 'Foo.DRuby.Org'], ['CN', 'Sample']]
  config[:SSLPrivateKeyAlgorithms] = ['ML-DSA-65']
  # Specify key exchange group.
  config[:SSLGroups] = 'SecP256r1MLKEM768'
  # Specify signature algorithm.
  config[:SSLSignatureAlgorithms] = 'mldsa65'

  DRb.start_service('drbssl://localhost:0', DRbTests::DRbEx.new, config)
  es = DRb::ExtServ.new(ARGV.shift, ARGV.shift)
  DRb.thread.join
  es.stop_service if es.alive?
end
