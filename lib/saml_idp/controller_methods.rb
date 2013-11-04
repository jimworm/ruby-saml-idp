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
      
      assertion = Nokogiri::XML::DocumentFragment.parse ''
      Nokogiri::XML::Builder.with(assertion) do
        Assertion('xmlns' => 'urn:oasis:names:tc:SAML:2.0:assertion', 'ID' => "_#{reference_id}", 'IssueInstant' => now.iso8601, 'Version' => '2.0') do
          Issuer decoded_saml_request[:issuer]
          Subject do
            NameID nameID, 'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            SubjectConfirmation('Method' => "urn:oasis:names:tc:SAML:2.0:cm:bearer") do
              SubjectConfirmationData('InResponseTo' => decoded_saml_request[:issuer], 'NotOnOrAfter' => (now+3*60).iso8601, 'Recipient' => decoded_saml_request[:acs_url])
            end
          end
          Conditions('NotBefore' => (now-5).iso8601, 'NotOnOrAfter' => (now+60*60).iso8601) do
            AudienceRestriction do
              Audience decoded_saml_request[:acs_url]
            end
          end
          AttributeStatement do
            Attribute('Name' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress') do
              AttributeValue nameID
            end
            if opts[:attributes] and opts[:attributes].is_a? Hash
              opts[:attributes].each do |name, value|
                Attribute('Name' => name) { AttributeValue value.to_s }
              end
            end
          end
          AuthnStatement('AuthnInstant' => now.iso8601, 'SessionIndex' => "_#{reference_id}") do
            AuthnContext do
              AuthnContextClassRef 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
            end
          end
        end
      end
      
      digest_value = Base64.strict_encode64(algorithm.digest(canonicalize(assertion)))
      
      signed_info = Nokogiri::XML::DocumentFragment.parse ''
      Nokogiri::XML::Builder.with(signed_info) do
        SignedInfo('xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#') do
          CanonicalizationMethod('Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#')
          SignatureMethod('Algorithm' => "http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm_name}")
          Reference('URI' => "#_#{reference_id}") do
            Transforms do
              Transform('Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature')
              Transform('Algorithm' => 'http://www.w3.org/2001/10/xml-exc-c14n#')
            end
            DigestMethod('Algorithm' => "http://www.w3.org/2000/09/xmldsig##{algorithm_name}")
            DigestValue digest_value
          end
        end
      end
      signed_info_ns = signed_info.at_css('SignedInfo').add_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
      signed_info.css('*').each{ |node| node.namespace = signed_info_ns }
      
      signature_value = sign(canonicalize(signed_info))
      
      keyinfo = Nokogiri::XML::DocumentFragment.parse ''
      Nokogiri::XML::Builder.with(keyinfo) do
        KeyInfo('xmlns' => 'http://www.w3.org/2000/09/xmldsig#') do
          X509Data do
            X509Certificate x509_certificate
          end
        end
      end
      
      signature = Nokogiri::XML::DocumentFragment.parse ''
      Nokogiri::XML::Builder.with(signature) do
        Signature('xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#') do
          SignatureValue signature_value
        end
      end
      signature_ns = signature.at_css('Signature').add_namespace('ds', 'http://www.w3.org/2000/09/xmldsig#')
      signature.css('*').each{ |node| node.namespace = signature_ns }
      
      signature.at_css('ds|SignatureValue', 'ds' => signature_ns.href).before(signed_info)
      signature.at_css('ds|SignatureValue', 'ds' => signature_ns.href).after(keyinfo)
      
      assertion.at_css('saml|Issuer', 'saml' => 'urn:oasis:names:tc:SAML:2.0:assertion').after(signature)
      
      saml_response = Nokogiri::XML::DocumentFragment.parse ''
      Nokogiri::XML::Builder.with(saml_response) do
        Response('ID' => "_#{response_id}", 'Version' => '2.0', 'IssueInstant' => now.iso8601, 'Destination' => decoded_saml_request[:acs_url], 'Consent' => 'urn:oasis:names:tc:SAML:2.0:consent:unspecified', 'InResponseTo' => decoded_saml_request[:issuer], 'xmlns:samlp' => 'urn:oasis:names:tc:SAML:2.0:protocol') do
          Issuer(decoded_saml_request[:issuer], 'xmlns' => 'urn:oasis:names:tc:SAML:2.0:assertion')
          Status do
            StatusCode('Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success')
          end
        end
      end
      
      saml_ns = saml_response.at_css('Response').add_namespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
      saml_response.at_css('*').namespace = saml_ns
      saml_response.at_css('Status').namespace = saml_ns
      saml_response.at_css('StatusCode').namespace = saml_ns
      
      saml_response.at_css('samlp|Status', 'samlp' => saml_ns.href).after(assertion)
      
      Base64.encode64(saml_response.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML))
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
      Base64.strict_encode64(key.sign(algorithm.new, data))
    end
    
    def canonicalize(builder)
      Nokogiri.parse(builder.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML)).canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
    end
  end
end
