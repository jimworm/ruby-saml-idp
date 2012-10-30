# encoding: utf-8
module SamlIdp
  module ControllerMethods
    attr_accessor :x509_certificate, :secret_key, :algorithm
    
    def algorithm=(new_algorithm)
      @algorithm = case new_algorithm
        when :sha256 then OpenSSL::Digest::SHA256
        when :sha384 then OpenSSL::Digest::SHA384
        when :sha512 then OpenSSL::Digest::SHA512
        when :sha1   then OpenSSL::Digest::SHA1
        else; fail 'Unknown algorithm'
      end
    end
    
    protected
    def decode_SAMLRequest(saml_request)
      zstream  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      decoded_request = Nokogiri::XML(zstream.inflate(Base64.decode64(saml_request)))
      decoded_request.remove_namespaces!
      zstream.finish
      zstream.close
      {acs_url: decoded_request.css('AuthnRequest').attribute('AssertionConsumerServiceURL').value, issuer: decoded_request.css('Issuer').text}
    end

    def encode_SAMLResponse(nameID, decoded_saml_request, opts = {})
      now = Time.now.utc
      response_id, reference_id = UUID.generate, UUID.generate
      audience_uri = opts[:audience_uri] || decoded_saml_request[:acs_url][/^(.*?\/\/.*?\/)/, 1]
      issuer_uri = opts[:issuer_uri] || (defined?(request) && request.url) || "http://example.com"
      
      extra_attributes = if opts[:attributes] and opts[:attributes].is_a? Hash
        opts[:attributes].map do |attr_name, value|
          "<Attribute Name=\"#{attr_name}\"><AttributeValue>" + value + "</AttributeValue></Attribute>"
        end.join
      else
        ''
      end
      

      assertion = %[<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_#{reference_id}" IssueInstant="#{now.iso8601}" Version="2.0"><Issuer>#{issuer_uri}</Issuer><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{nameID}</NameID><SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><SubjectConfirmationData InResponseTo="#{decoded_saml_request[:issuer]}" NotOnOrAfter="#{(now+3*60).iso8601}" Recipient="#{decoded_saml_request[:acs_url]}"></SubjectConfirmationData></SubjectConfirmation></Subject><Conditions NotBefore="#{(now-5).iso8601}" NotOnOrAfter="#{(now+60*60).iso8601}"><AudienceRestriction><Audience>#{audience_uri}</Audience></AudienceRestriction></Conditions><AttributeStatement><Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><AttributeValue>#{nameID}</AttributeValue></Attribute>#{extra_attributes}</AttributeStatement><AuthnStatement AuthnInstant="#{now.iso8601}" SessionIndex="_#{reference_id}"><AuthnContext><AuthnContextClassRef>urn:federation:authentication:windows</AuthnContextClassRef></AuthnContext></AuthnStatement></Assertion>]

      digest_value = Base64.encode64(algorithm.digest(assertion)).gsub(/\n/, '')

      signed_info = %[<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}"></ds:SignatureMethod><ds:Reference URI="#_#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig##{algorithm_name}"></ds:DigestMethod><ds:DigestValue>#{digest_value}</ds:DigestValue></ds:Reference></ds:SignedInfo>]

      signature_value = sign(signed_info).gsub(/\n/, '')

      signature = %[<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">#{signed_info}<ds:SignatureValue>#{signature_value}</ds:SignatureValue><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>#{x509_certificate}</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature>]

      assertion_and_signature = assertion.sub(/Issuer\>\<Subject/, "Issuer>#{signature}<Subject")

      xml = %[<samlp:Response ID="_#{response_id}" Version="2.0" IssueInstant="#{now.iso8601}" Destination="#{decoded_saml_request[:acs_url]}" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="#{decoded_saml_request[:issuer]}" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">#{issuer_uri}</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status>#{assertion_and_signature}</samlp:Response>]

      Base64.encode64(xml)
    end
    
    def x509_certificate
      @x509_certificate || SamlIdp.config.x509_certificate
    end

    def secret_key
      @secret_key || SamlIdp.config.secret_key
    end

    def algorithm
      self.algorithm = SamlIdp.config.algorithm unless @algorithm
      @algorithm
    end

    def algorithm_name
      algorithm.to_s.split('::').last.downcase
    end
    
    private
    def sign(data)
      key = OpenSSL::PKey::RSA.new(self.secret_key)
      Base64.encode64(key.sign(algorithm.new, data))
    end
  end
end
