# frozen_string_literal: false
require 'test/unit'
require_relative 'drbtest'

begin
  require 'drb/ssl'
rescue LoadError
end

module DRbTests

if Object.const_defined?('OpenSSL')

class TestSSLConfig < Test::Unit::TestCase
  include DRbPQCUtilities

  CERT_NAME = [['C', 'JP'], ['O', 'Foo.DRuby.Org'], ['CN', 'localhost']]

  def test_setup_certificate_default
    config = {
      SSLCertName: CERT_NAME
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::RSA, certs[0][1])
  end

  def test_setup_certificate_rsa
    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['RSA']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::RSA, certs[0][1])
  end

  def test_setup_certificate_ml_dsa_44
    omit_unless_support_pqc

    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['ML-DSA-44']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::PKey, certs[0][1])
    assert_match(/type_name=ML-DSA-44/, certs[0][1].inspect)
  end

  def test_setup_certificate_ml_dsa_65
    omit_unless_support_pqc

    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['ML-DSA-65']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::PKey, certs[0][1])
    assert_match(/type_name=ML-DSA-65/, certs[0][1].inspect)
  end

  def test_setup_certificate_ml_dsa_87
    omit_unless_support_pqc

    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['ML-DSA-87']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::PKey, certs[0][1])
    assert_match(/type_name=ML-DSA-87/, certs[0][1].inspect)
  end

  def test_setup_certificate_ml_dsa_65_rsa
    omit_unless_support_pqc

    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['ML-DSA-65', 'RSA']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_instance_of(Array, certs)
    assert_equal(2, certs.length)
    assert_instance_of(OpenSSL::X509::Certificate, certs[0][0])
    assert_instance_of(OpenSSL::PKey::PKey, certs[0][1])
    assert_match(/type_name=ML-DSA-65/, certs[0][1].inspect)
    assert_instance_of(OpenSSL::X509::Certificate, certs[1][0])
    assert_instance_of(OpenSSL::PKey::RSA, certs[1][1])
  end

  def test_setup_certificate_invalid_algorithm
    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['INVALID']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    error = assert_raise(DRb::DRbBadConfig) do
      ssl_conf.setup_certificate
    end
    assert_equal('INVALID algorithm not found. '\
                 'RSA, ML-DSA-44, ML-DSA-65, and ML-DSA-87 '\
                 'algorithms are supported',
                 error.message)
  end

  def test_setup_certificate_unsupported_mldsa
    unless OpenSSL::PKey.respond_to?(:generate_key)
      omit 'OpenSSL::PKey.generate_key not available'
    end

    orig = OpenSSL::PKey.method(:generate_key)
    OpenSSL::PKey.define_singleton_method(:generate_key) do |alg|
      raise OpenSSL::PKey::PKeyError, 'algorithm ML-DSA-65 not found'
    end
    begin
      config = {
        SSLCertName: CERT_NAME,
        SSLPrivateKeyAlgorithms: ['ML-DSA-65']
      }
      ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
      error = assert_raise(DRb::DRbBadConfig) do
        ssl_conf.setup_certificate
      end
      assert_equal('ML-DSA-65 algorithm not supported. '\
                   'Install openssl gem >= 4.0.0 '\
                   'building with OpenSSL >= 3.5.0',
                   error.message)
    ensure
      OpenSSL::PKey.define_singleton_method(
        :generate_key, orig)
    end
  end

  def test_setup_certificate_preserves_existing_cert_and_key
    pkey = Fixtures.read_pkey('rsa_server.key')
    cert = Fixtures.read_cert('rsa_server.crt')
    config = {
      SSLCertificate: cert,
      SSLPrivateKey: pkey
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_same(cert, certs[0][0])
    assert_same(pkey, certs[0][1])
  end

  def test_setup_ssl_context_sigalgs
    ctx_class = OpenSSL::SSL::SSLContext
    omit 'sigalgs= not supported' unless ctx_class.method_defined?(:sigalgs=)

    config = {
      SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
      SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
      SSLSignatureAlgorithms: 'rsa_pss_rsae_sha256'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_sigalgs_pqc
    ctx_class = OpenSSL::SSL::SSLContext
    omit 'sigalgs= not supported' unless ctx_class.method_defined?(:sigalgs=)
    omit_unless_support_pqc

    config = {
      SSLCertificates: [
        [Fixtures.read_cert('mldsa65_server.crt'),
         Fixtures.read_pkey('mldsa65_server.key')],
        [Fixtures.read_cert('rsa_server.crt'),
         Fixtures.read_pkey('rsa_server.key')]
      ],
      SSLSignatureAlgorithms: 'mldsa65:rsa_pss_rsae_sha256'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_sigalgs_method_not_supported
    ctx_class = OpenSSL::SSL::SSLContext
    unless ctx_class.method_defined?(:sigalgs=)
      omit 'sigalgs= already not supported'
    end

    orig = ctx_class.instance_method(:sigalgs=)
    ctx_class.undef_method(:sigalgs=)
    begin
      config = {
        SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
        SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
        SSLSignatureAlgorithms: 'rsa_pss_rsae_sha256'
      }
      ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
      error = assert_raise(DRb::DRbBadConfig) do
        ssl_conf.setup_ssl_context
      end
      assert_equal(':SSLSignatureAlgorithms not supported. '\
                   'Install openssl gem >= 4.0.0 '\
                   'building with OpenSSL >= 1.0.2',
                   error.message)
    ensure
      ctx_class.define_method(:sigalgs=, orig)
    end
  end

  def test_setup_ssl_context_client_sigalgs
    ctx_class = OpenSSL::SSL::SSLContext
    unless ctx_class.method_defined?(:client_sigalgs=)
      omit 'client_sigalgs= not supported'
    end

    config = {
      SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
      SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
      SSLClientSignatureAlgorithms: 'rsa_pss_rsae_sha256'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_client_sigalgs_pqc
    ctx_class = OpenSSL::SSL::SSLContext
    unless ctx_class.method_defined?(:client_sigalgs=)
      omit 'client_sigalgs= not supported'
    end
    omit_unless_support_pqc

    config = {
      SSLCertificate: Fixtures.read_cert('mldsa65_server.crt'),
      SSLPrivateKey: Fixtures.read_pkey('mldsa65_server.key'),
      SSLClientSignatureAlgorithms: 'mldsa44:mldsa65:mldsa87'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_client_sigalgs_not_supported
    ctx_class = OpenSSL::SSL::SSLContext
    unless ctx_class.method_defined?(:client_sigalgs=)
      omit 'client_sigalgs= already not supported'
    end

    orig = ctx_class.instance_method(:client_sigalgs=)
    ctx_class.undef_method(:client_sigalgs=)
    begin
      config = {
        SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
        SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
        SSLClientSignatureAlgorithms: 'rsa_pss_rsae_sha256'
      }
      ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
      error = assert_raise(DRb::DRbBadConfig) do
        ssl_conf.setup_ssl_context
      end
      assert_equal(':SSLClientSignatureAlgorithms not supported. '\
                   'Install openssl gem >= 4.0.0 '\
                   'building with OpenSSL >= 1.0.2',
                   error.message)
    ensure
      ctx_class.define_method(:client_sigalgs=, orig)
    end
  end

  def test_setup_ssl_context_groups
    ctx_class = OpenSSL::SSL::SSLContext
    omit 'groups= not supported' unless ctx_class.method_defined?(:groups=)

    config = {
      SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
      SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
      SSLGroups: 'P-256:P-384'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_groups_pqc
    ctx_class = OpenSSL::SSL::SSLContext
    omit 'groups= not supported' unless ctx_class.method_defined?(:groups=)
    omit_unless_support_pqc

    config = {
      SSLCertificate: Fixtures.read_cert('mldsa65_server.crt'),
      SSLPrivateKey: Fixtures.read_pkey('mldsa65_server.key'),
      SSLGroups: 'X25519MLKEM768'
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_ssl_context
    ssl_ctx = ssl_conf.instance_variable_get(:@ssl_ctx)

    assert_instance_of(OpenSSL::SSL::SSLContext, ssl_ctx)
  end

  def test_setup_ssl_context_groups_not_supported
    ctx_class = OpenSSL::SSL::SSLContext
    unless ctx_class.method_defined?(:groups=)
      omit 'groups= already not supported'
    end

    orig = ctx_class.instance_method(:groups=)
    ctx_class.undef_method(:groups=)
    begin
      config = {
        SSLCertificate: Fixtures.read_cert('rsa_server.crt'),
        SSLPrivateKey: Fixtures.read_pkey('rsa_server.key'),
        SSLGroups: 'P-256:P-384'
      }
      ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
      error = assert_raise(DRb::DRbBadConfig) do
        ssl_conf.setup_ssl_context
      end
      assert_equal(':SSLGroups not supported. '\
                   'Install openssl gem >= 4.0.0',
                   error.message)
    ensure
      ctx_class.define_method(:groups=, orig)
    end
  end
end

end

end
