# encoding: utf-8
module SamlIdp
  require 'openssl'
  require 'base64'
  require 'cgi'
  require 'time'
  require 'uuid'
  require 'nokogiri'
  require 'saml_idp/configurator'
  require 'saml_idp/controller_methods'
  require 'saml_idp/default'
  require 'saml_idp/version'
  require 'saml_idp/engine' if defined?(::Rails) && Rails::VERSION::MAJOR > 2

  def self.config=(config)
    @config = config
  end

  def self.config
    @config ||= SamlIdp::Configurator.new
  end

end

