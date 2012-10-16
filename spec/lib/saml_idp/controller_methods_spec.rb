# encoding: utf-8
require 'spec_helper'

describe "SamlIdp::ControllerMethods" do
  let(:controller) do
    Class.new do
      include SamlIdp::ControllerMethods
    end.new
  end
  let(:acs_url) { 'https://example.com/saml/consume' }
  let(:issuer)  { 'https://example.com/issuer'}

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
      let(:decoded) { {acs_url: acs_url, issuer: issuer} }
      
      context "with default hash alogrithm" do
        it "returns a valid SAML response" do
          saml_response = controller.send(:encode_SAMLResponse, "foo@example.com", decoded)
          response = Onelogin::Saml::Response.new(saml_response)
          response.name_id.should == "foo@example.com"
          response.issuer.should == "http://example.com"
          response.settings = saml_settings
          response.is_valid?.should be_true
        end
      end
      
      pending "add :sha384 and :sha512 on release of ruby-saml v0.5.4"
      [:sha1, :sha256].each do |scheme|
        context "with hash algorithms set to #{scheme}" do
          it "returns a valid SAML response" do
            controller.algorithm = scheme
            saml_response = controller.send(:encode_SAMLResponse, "foo@example.com", decoded)
            response = Onelogin::Saml::Response.new(saml_response)
            response.name_id.should == "foo@example.com"
            response.issuer.should == "http://example.com"
            response.settings = saml_settings
            response.is_valid?.should be_true
          end
        end
      end
    end
  end
end
