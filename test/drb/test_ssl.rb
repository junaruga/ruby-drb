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
  include DRbPQC

  CERT_NAME = [['C', 'JP'], ['O', 'Foo.DRuby.Org'], ['CN', 'localhost']]

  def test_setup_certificate_default
    config = {
      SSLCertName: CERT_NAME
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_equal([[OpenSSL::X509::Certificate, OpenSSL::PKey::RSA]],
                 certs.collect {|cert| cert.collect(&:class)})
  end

  def test_setup_certificate_rsa
    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['RSA']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    ssl_conf.setup_certificate
    certs = ssl_conf.instance_variable_get(:@certs)

    assert_equal([[OpenSSL::X509::Certificate, OpenSSL::PKey::RSA]],
                 certs.collect {|cert| cert.collect(&:class)})
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

    assert_equal([[OpenSSL::X509::Certificate, OpenSSL::PKey::PKey]],
                 certs.collect {|cert| cert.collect(&:class)})
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

    assert_equal([[OpenSSL::X509::Certificate, OpenSSL::PKey::PKey]],
                 certs.collect {|cert| cert.collect(&:class)})
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

    assert_equal([[OpenSSL::X509::Certificate, OpenSSL::PKey::PKey]],
                 certs.collect {|cert| cert.collect(&:class)})
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

    assert_equal([
                   [OpenSSL::X509::Certificate, OpenSSL::PKey::PKey],
                   [OpenSSL::X509::Certificate, OpenSSL::PKey::RSA]
                 ],
                 certs.collect {|cert| cert.collect(&:class)})
    assert_match(/type_name=ML-DSA-65/, certs[0][1].inspect)
  end

  def test_setup_certificate_invalid_algorithm
    config = {
      SSLCertName: CERT_NAME,
      SSLPrivateKeyAlgorithms: ['INVALID']
    }
    ssl_conf = DRb::DRbSSLSocket::SSLConfig.new(config)
    message = 'INVALID algorithm not found. ' \
              'RSA, ML-DSA-44, ML-DSA-65, and ML-DSA-87 ' \
              'algorithms are supported'
    assert_raise_with_message(ArgumentError, message) do
      ssl_conf.setup_certificate
    end
  end

  # Test that setup_certificate preserves the original cert/key objects.
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

  # Test setup_ssl_context with :SSLSignatureAlgorithms config option.
  def test_setup_ssl_context_sigalgs
    # #setup_ssl_context requires OpenSSL::SSL::SSLContext#sigalgs= introduced
    # on Ruby OpenSSL >= 4.0.
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

  # Test setup_ssl_context with :SSLSignatureAlgorithms config option.
  # Similar to test_setup_ssl_context_sigalgs but with ML-DSA and RSA
  # multiple certificates for the PQC migration use case.
  def test_setup_ssl_context_sigalgs_pqc
    # #setup_ssl_context requires OpenSSL::SSL::SSLContext#sigalgs= introduced
    # on Ruby OpenSSL >= 4.0.
    ctx_class = OpenSSL::SSL::SSLContext
    omit 'sigalgs= not supported' unless ctx_class.method_defined?(:sigalgs=)
    # Requires PQC support on OpenSSL >= 3.5.
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
      error = assert_raise(NoMethodError) do
        ssl_conf.setup_ssl_context
      end
      assert_equal("undefined method 'client_sigalgs=' for "\
                   "an instance of OpenSSL::SSL::SSLContext",
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
      error = assert_raise(NoMethodError) do
        ssl_conf.setup_ssl_context
      end
      assert_equal("undefined method 'groups=' for "\
                   "an instance of OpenSSL::SSL::SSLContext",
                   error.message)
    ensure
      ctx_class.define_method(:groups=, orig)
    end
  end
end

end

end
