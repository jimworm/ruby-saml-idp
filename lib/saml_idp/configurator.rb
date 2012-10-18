# encoding: utf-8
module SamlIdp
  class Configurator
    attr_accessor :x509_certificate, :secret_key, :algorithm

    def initialize(options = {})
      defaults = {
        x509_certificate: Default::X509_CERTIFICATE,
        secret_key: Default::SECRET_KEY,
        algorithm: :sha1
      }
      options = defaults.merge(options)
      self.x509_certificate = options[:x509_certificate]
      self.secret_key = options[:secret_key]
      self.algorithm = options[:algorithm]
    end
  end
end
