# frozen_string_literal: false
require_relative 'drbtest'

begin
  require 'drb/ssl'
rescue LoadError
end

module DRbTests

if Object.const_defined?("OpenSSL")


class DRbSSLService < DRbService
  %w(ut_drb_drbssl.rb ut_array_drbssl.rb).each do |nm|
    add_service_command(nm)
  end

  def start
    config = Hash.new

    config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_PEER
    config[:SSLVerifyCallback] = lambda{ |ok,x509_store|
      true
    }
    if RUBY_PLATFORM.match?(/openbsd/)
      config[:SSLMinVersion] = OpenSSL::SSL::TLS1_2_VERSION
      config[:SSLMaxVersion] = OpenSSL::SSL::TLS1_2_VERSION
    end
    begin
      data = open("sample.key"){|io| io.read }
      config[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(data)
      data = open("sample.crt"){|io| io.read }
      config[:SSLCertificate] = OpenSSL::X509::Certificate.new(data)
    rescue
      # $stderr.puts "Switching to use self-signed certificate"
      config[:SSLCertName] =
        [ ["C","JP"], ["O","Foo.DRuby.Org"], ["CN", "Sample"] ]
    end

    @server = DRb::DRbServer.new('drbssl://localhost:0', manager, config)
  end
end

class TestDRbSSLCore < Test::Unit::TestCase
  include DRbCore
  def setup
    if RUBY_PLATFORM.match?(/mswin|mingw/)
      @omitted = true
      omit 'This test seems to randomly hang on Windows'
    end
    @drb_service = DRbSSLService.new
    super
    setup_service 'ut_drb_drbssl.rb'
  end

  def test_02_unknown
  end

  def test_01_02_loop
  end

  def test_05_eq
  end
end

class TestDRbSSLAry < Test::Unit::TestCase
  include DRbAry
  def setup
    if RUBY_PLATFORM.match?(/mswin|mingw/)
      @omitted = true
      omit 'This test seems to randomly hang on Windows'
    end
    LeakChecker.skip if defined?(LeakChecker)
    @drb_service = DRbSSLService.new
    super
    setup_service 'ut_array_drbssl.rb'
  end
end

# Test drbssl protocol with auto-generated PQC-supported ML-DSA-65 certificate
# and PQC-supported ML-KEM key exchange (X25519MLKEM768).
class TestDRbSSLPQC < Test::Unit::TestCase
  include DRbPQC

  def setup
    omit_unless_support_pqc

    server_config = {
      SSLCertName: [['C', 'JP'], ['O', 'Foo.DRuby.Org'],
                    ['CN', 'Sample']],
      SSLPrivateKeyAlgorithms: ['ML-DSA-65'],
      SSLGroups: 'X25519MLKEM768',
      SSLSignatureAlgorithms: 'mldsa65',
      SSLVerifyMode: OpenSSL::SSL::VERIFY_PEER
    }
    @server = DRb::DRbServer.new('drbssl://localhost:0', nil,
                                 server_config)
  end

  def teardown
    @server&.stop_service
  end

  def test_group_sigalg
    client_config = {
      SSLGroups: 'X25519MLKEM768',
      SSLSignatureAlgorithms: 'mldsa65',
      SSLVerifyMode: OpenSSL::SSL::VERIFY_PEER,
      SSLVerifyCallback: lambda { |ok, x509_store|
        true
      }
    }
    DRb.start_service(nil, nil, client_config)

    # Test client connection
    DRb::DRbConn.open(@server.uri) do |conn|
      # ssl: OpenSSL::SSL::SSLSocket instance
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_equal('X25519MLKEM768', ssl.group)
      assert_nil(ssl.sigalg)
      assert_equal('mldsa65', ssl.peer_sigalg)
      [true, nil]
    end
  ensure
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end
end

# Test drbssl protocol with pre-generated ML-DSA-65 (PQC) and RSA (non-PQC)
# multiple server certificates, PQC-supported ML-KEM key exchange
# (SecP384r1MLKEM1024), and client certificate verification with both ML-DSA-65
# and RSA signature algorithms.
class TestDRbSSLPQCMultipleCert < Test::Unit::TestCase
  include DRbPQC

  def setup
    omit_unless_support_pqc

    store = OpenSSL::X509::Store.new
    store.add_cert(Fixtures.read_cert('mldsa65_ca.crt'))
    store.add_cert(Fixtures.read_cert('rsa_ca.crt'))
    server_config = {
      SSLCertificates: [
        [Fixtures.read_cert('mldsa65_server.crt'),
         Fixtures.read_pkey('mldsa65_server.key')],
        [Fixtures.read_cert('rsa_server.crt'),
         Fixtures.read_pkey('rsa_server.key')]
      ],
      SSLGroups: 'SecP384r1MLKEM1024',
      SSLSignatureAlgorithms: 'mldsa65:rsa_pss_rsae_sha256',
      # CA certificates to verify client's certificate (mldsa65_client.crt or
      # rsa_client.crt)
      SSLCertificateStore: store,
      # CA certificate(s) sent to the client indicating which certificates the
      # server accepts. Helps the client choose which certificate to present.
      SSLClientCA: [
        Fixtures.read_cert('mldsa65_ca.crt'),
        Fixtures.read_cert('rsa_ca.crt')
      ],
      SSLVerifyMode: OpenSSL::SSL::VERIFY_PEER |
                     OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    }
    @server = DRb::DRbServer.new('drbssl://localhost:0', nil,
                                 server_config)
  end

  def teardown
    @server&.stop_service
  end

  def test_group_sigalg_mldsa65
    client_config = {
      SSLCertificate: Fixtures.read_cert('mldsa65_client.crt'),
      SSLPrivateKey: Fixtures.read_pkey('mldsa65_client.key'),
      SSLGroups: 'SecP384r1MLKEM1024',
      SSLSignatureAlgorithms: 'mldsa65',
      SSLCACertificateFile: Fixtures.file_path('mldsa65_ca.crt'),
      SSLVerifyMode: OpenSSL::SSL::VERIFY_PEER |
                     OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    }
    DRb.start_service(nil, nil, client_config)

    # Test client connection
    DRb::DRbConn.open(@server.uri) do |conn|
      # ssl: OpenSSL::SSL::SSLSocket instance
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_equal('SecP384r1MLKEM1024', ssl.group)
      assert_equal('mldsa65', ssl.sigalg)
      assert_equal('mldsa65', ssl.peer_sigalg)
      [true, nil]
    end
  ensure
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end

  def test_group_sigalg_rsa
    client_config = {
      SSLCertificate: Fixtures.read_cert('rsa_client.crt'),
      SSLPrivateKey: Fixtures.read_pkey('rsa_client.key'),
      SSLGroups: 'SecP384r1MLKEM1024',
      SSLSignatureAlgorithms: 'rsa_pss_rsae_sha256',
      SSLCACertificateFile: Fixtures.file_path('rsa_ca.crt'),
      SSLVerifyMode: OpenSSL::SSL::VERIFY_PEER |
                     OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    }
    DRb.start_service(nil, nil, client_config)

    # Test client connection
    DRb::DRbConn.open(@server.uri) do |conn|
      # ssl: OpenSSL::SSL::SSLSocket instance
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_equal('SecP384r1MLKEM1024', ssl.group)
      assert_equal('rsa_pss_rsae_sha256', ssl.sigalg)
      assert_equal('rsa_pss_rsae_sha256', ssl.peer_sigalg)
      [true, nil]
    end
  ensure
    DRb.stop_service
    DRb::DRbConn.stop_pool
  end
end

end

end
