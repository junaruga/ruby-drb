# frozen_string_literal: false

# This file does not require test/unit unlike drbtest.rb because it can
# be loaded by child processes (ut_*.rb) where
# test-unit's at_exit autorunner would cause errors.

require 'openssl'

module DRbTests

module Fixtures
  module_function

  def file_path(name)
    File.join(__dir__, 'fixtures', name)
  end

  def read_file(name)
    @file_cache ||= {}
    @file_cache[name] ||= File.read(file_path(name))
  end

  # Raises OpenSSL::PKey::PKeyError when reading an ML-DSA-65 key file
  # with old OpenSSL versions.
  def read_pkey(name)
    OpenSSL::PKey.read(read_file(name))
  end

  def read_cert(name)
    OpenSSL::X509::Certificate.new(read_file(name))
  end
end

end
