module SamlRequestMacros
  def make_saml_request(options = {})
    auth_request = Onelogin::Saml::Authrequest.new
    auth_url = auth_request.create(saml_settings(options))
    CGI.unescape(auth_url.split("=").last)
  end

  def saml_settings(options = {})
    defaults = {issuer: "http://example.com/issuer",
                acs_url: "https://foo.example.com/saml/consume",
                target: "http://idp.com/saml/idp"}
    options = defaults.merge(options)
    settings = Onelogin::Saml::Settings.new
    settings.assertion_consumer_service_url = options[:acs_url]
    settings.issuer = options[:issuer]
    settings.idp_sso_target_url = options[:target]
    settings.idp_cert_fingerprint = SamlIdp::Default::FINGERPRINT
    settings.name_identifier_format = SamlIdp::Default::NAME_ID_FORMAT
    settings
  end
end
