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

class DRbSSLPQCService < DRbService
  %w(ut_drb_drbssl_pqc.rb).each do |nm|
    add_service_command(nm)
  end

  def start
    config = Hash.new

    # This config is used for both server and client connections.
    # As a server: verify the client's certificate.
    # As a client: verify the child server's self-signed certificate via
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

    @server = DRb::DRbServer.new('drbssl://localhost:0', manager, config)
  end
end

# Test drbssl protocol with auto-generated PQC-supported ML-DSA-65 certificate
# and PQC-supported ML-KEM key exchange (SecP256r1MLKEM768).
class TestDRbSSLPQC < Test::Unit::TestCase
  include DRbPQC

  def setup
    if RUBY_PLATFORM.match?(/mswin|mingw/)
      @omitted = true
      omit 'This test seems to randomly hang on Windows'
    end
    omit_unless_support_pqc do
      @omitted = true
    end

    @drb_service = DRbSSLPQCService.new
    super
    setup_service 'ut_drb_drbssl_pqc.rb'
  end

  def test_group_sigalg
    # Server connection
    assert_equal('OpenSSL::SSL::SSLSocket',
                 @there.stream_class_name)
    server_ssl = @there.stream
    assert_equal('SecP256r1MLKEM768', server_ssl.group)
    assert_equal('mldsa65', server_ssl.sigalg)
    assert_nil(server_ssl.peer_sigalg)

    # Client connection
    DRb::DRbConn.open(@there.__drburi) do |conn|
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_instance_of(OpenSSL::SSL::SSLSocket, ssl)
      assert_equal('SecP256r1MLKEM768', ssl.group)
      assert_nil(ssl.sigalg)
      assert_equal('mldsa65', ssl.peer_sigalg)
      [true, nil]
    end
  end
end

class DRbSSLPQCMultiCertMLDSA65Service < DRbService
  %w(ut_drb_drbssl_pqc_multi_cert.rb).each do |nm|
    add_service_command(nm)
  end

  def start
    # Manager config with pre-generated ML-DSA-65 certificate so the child
    # server can verify the manager's certificate via mldsa65_ca.crt in its
    # store when connecting back as a client.
    # This config is used for only server connections
    # (DRb::DRbSSLSocket.open_server), because the following client_config
    # overrides client connection (DRb::DRbSSLSocket.open) with client_config.
    manager_config = Hash.new
    manager_config[:SSLCertificate] = OpenSSL::X509::Certificate.new(
      Fixtures.read_file('mldsa65_server.crt'))
    manager_config[:SSLPrivateKey] = OpenSSL::PKey.read(
      Fixtures.read_file('mldsa65_server.key'))
    manager_config[:SSLSignatureAlgorithms] = 'mldsa65'
    manager_config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_NONE
    @server = DRb::DRbServer.new('drbssl://localhost:0', manager,
                                 manager_config)

    # This config is used for only client connection to the child server.
    # The following service overrides client connection (DRb::DRbSSLSocket.open)
    # with client_config.
    client_config = Hash.new
    client_config[:SSLCertificate] = OpenSSL::X509::Certificate.new(
      Fixtures.read_file('mldsa65_client.crt'))
    client_config[:SSLPrivateKey] = OpenSSL::PKey.read(
      Fixtures.read_file('mldsa65_client.key'))
    client_config[:SSLSignatureAlgorithms] = 'mldsa65'
    # CA certificate to verify the child server's certificate.
    client_config[:SSLCACertificateFile] =
      Fixtures.file_path('mldsa65_ca.crt')
    # Verify the child server's certificate and require the child server
    # to verify this client's certificate.
    client_config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_PEER |
                                    OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    # Start a client-only DRb service (no URI, no front object) to set
    # client_config as DRb.config.
    DRb.start_service(nil, nil, client_config)
  end
end

class DRbSSLPQCMultiCertRSAService < DRbService
  %w(ut_drb_drbssl_pqc_multi_cert.rb).each do |nm|
    add_service_command(nm)
  end

  def start
    # Manager config with pre-generated RSA certificate so the child
    # server can verify the manager's certificate via rsa_ca.crt in its
    # store when connecting back as a client.
    # This config is used for only server connections
    # (DRb::DRbSSLSocket.open_server), because the following client_config
    # overrides client connection (DRb::DRbSSLSocket.open) with client_config.
    manager_config = Hash.new
    manager_config[:SSLCertificate] = OpenSSL::X509::Certificate.new(
      Fixtures.read_file('rsa_server.crt'))
    manager_config[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(
      Fixtures.read_file('rsa_server.key'))
    manager_config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_NONE
    @server = DRb::DRbServer.new('drbssl://localhost:0', manager,
                                 manager_config)

    # This config is used for only client connection to the child server.
    # The following service overrides client connection (DRb::DRbSSLSocket.open)
    # with client_config.
    client_config = Hash.new
    client_config[:SSLCertificate] = OpenSSL::X509::Certificate.new(
      Fixtures.read_file('rsa_client.crt'))
    client_config[:SSLPrivateKey] = OpenSSL::PKey::RSA.new(
      Fixtures.read_file('rsa_client.key'))
    client_config[:SSLSignatureAlgorithms] = 'rsa_pss_rsae_sha256'
    # CA certificate to verify the child server's certificate.
    client_config[:SSLCACertificateFile] =
      Fixtures.file_path('rsa_ca.crt')
    # Verify the child server's certificate and require the child server
    # to verify this client's certificate.
    client_config[:SSLVerifyMode] = OpenSSL::SSL::VERIFY_PEER |
                                    OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT
    # Start a client-only DRb service (no URI, no front object) to set
    # client_config as DRb.config.
    DRb.start_service(nil, nil, client_config)
  end
end

# Test drbssl protocol with pre-generated ML-DSA-65 (PQC) and RSA (non-PQC) dual
# server certificates, PQC-supported ML-KEM key exchange (X25519MLKEM768), and
# ML-DSA-65 client certificate verification.
class TestDRbSSLPQCMultiCertMLDSA65 < Test::Unit::TestCase
  include DRbPQC

  def setup
    if RUBY_PLATFORM.match?(/mswin|mingw/)
      @omitted = true
      omit 'This test seems to randomly hang on Windows'
    end
    omit_unless_support_pqc do
      @omitted = true
    end

    @drb_service = DRbSSLPQCMultiCertMLDSA65Service.new
    super
    setup_service 'ut_drb_drbssl_pqc_multi_cert.rb'
  end

  def test_group_sigalg
    # Server connection
    assert_equal('OpenSSL::SSL::SSLSocket',
                 @there.stream_class_name)
    server_ssl = @there.stream
    assert_equal('X25519MLKEM768', server_ssl.group)
    assert_equal('mldsa65', server_ssl.sigalg)
    assert_equal('mldsa65', server_ssl.peer_sigalg)

    # Client connection
    DRb::DRbConn.open(@there.__drburi) do |conn|
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_instance_of(OpenSSL::SSL::SSLSocket, ssl)
      assert_equal('X25519MLKEM768', ssl.group)
      assert_equal('mldsa65', ssl.sigalg)
      assert_equal('mldsa65', ssl.peer_sigalg)
      [true, nil]
    end
  end
end

# Test drbssl protocol with pre-generated ML-DSA-65 (PQC) and RSA (non-PQC) dual
# server certificates, PQC-supported ML-KEM key exchange (X25519MLKEM768), and
# RSA client certificate verification.
class TestDRbSSLPQCMultiCertRSA < Test::Unit::TestCase
  include DRbPQC

  def setup
    if RUBY_PLATFORM.match?(/mswin|mingw/)
      @omitted = true
      omit 'This test seems to randomly hang on Windows'
    end
    omit_unless_support_pqc do
      @omitted = true
    end

    @drb_service = DRbSSLPQCMultiCertRSAService.new
    super
    setup_service 'ut_drb_drbssl_pqc_multi_cert.rb'
  end

  def test_group_sigalg
    # Server connection
    assert_equal('OpenSSL::SSL::SSLSocket',
                 @there.stream_class_name)
    server_ssl = @there.stream
    assert_equal('X25519MLKEM768', server_ssl.group)
    assert_equal('rsa_pss_rsae_sha256', server_ssl.sigalg)
    assert_equal('rsa_pss_rsae_sha256', server_ssl.peer_sigalg)

    # Client connection
    DRb::DRbConn.open(@there.__drburi) do |conn|
      ssl = conn.instance_variable_get(:@protocol).stream
      assert_instance_of(OpenSSL::SSL::SSLSocket, ssl)
      assert_equal('X25519MLKEM768', ssl.group)
      assert_equal('rsa_pss_rsae_sha256', ssl.sigalg)
      assert_equal('rsa_pss_rsae_sha256', ssl.peer_sigalg)
      [true, nil]
    end
  end
end

end

end
