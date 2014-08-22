# encoding: utf-8
require 'spec_helper'

describe "SamlIdp::ControllerMethods" do
  let(:controller) do
    Class.new do
      include SamlIdp::ControllerMethods
    end.new
  end
  let(:acs_url) { 'https://example.com/saml/consume' }
  let(:issuer)  { 'example.com'}

  describe "public methods" do
    describe "#decode_SAMLRequest" do
      let(:decoded) { controller.send(:decode_SAMLRequest, make_saml_request(acs_url: acs_url, issuer: issuer)) }
      
      it "returns the correct acs url" do
        decoded[:acs_url].should == acs_url
      end
      
      it "returns the correct issuer" do
        decoded[:issuer].should == issuer
      end
    end
  
    describe "#encode_SAMLRequest" do
      let(:decoded)     { {acs_url: acs_url, issuer: issuer} }
      let(:extra_attrs) { { 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname' => 'Patrick',
                            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'   => 'Bateman',
                            'alias'                                                           => 'I <3 Batman & Robin' } }
      
      context "with default hash alogrithm" do
        it "returns a valid SAML assertion" do
          saml_response = controller.send(:encode_SAMLResponse, "foo@example.com", decoded)
          # XMLSecurity::SignedDocument.any_instance.stub(:validate_doc).and_raise('fuck')
          response = OneLogin::RubySaml::Saml::Response.new(saml_response)
          response.settings = saml_settings
          response.send :validate, false
          response.is_valid?.should be_true
          
          response.name_id.should == "foo@example.com"
          response.issuer.should == "example.com"
        end
        
        it "returns a SAML assertion with extra attributes" do
          saml_response = controller.send(:encode_SAMLResponse, "foo@example.com", decoded, attributes: extra_attrs)
          response = OneLogin::RubySaml::Saml::Response.new(saml_response)
          response.settings = saml_settings
          response.send :validate, false
          # response.is_valid?.should be_true
          
          response.name_id.should == "foo@example.com"
          response.issuer.should == "example.com"
          
          response.attributes['alias'].should == 'I <3 Batman & Robin'
          response.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname'].should == 'Patrick'
          response.attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname'].should == 'Bateman'
          
        end
      end
      
      [:sha1, :sha256, :sha384, :sha512].each do |scheme|
        context "with hash algorithms set to #{scheme}" do
          it "returns a valid SAML response" do
            controller.algorithm = scheme
            saml_response = controller.send(:encode_SAMLResponse, "foo@example.com", decoded)
            response = OneLogin::RubySaml::Saml::Response.new(saml_response)
            response.name_id.should == "foo@example.com"
            response.issuer.should == "example.com"
            response.settings = saml_settings
            response.is_valid?.should be_true
          end
        end
      end
    end
  end
end
