# encoding: utf-8
require 'spec_helper'

describe SamlIdp::IdpController do
  
  let(:acs_url)       { 'https://example.com/saml/consume' }
  let(:issuer)        { 'example.com'}
  let(:saml_request)  { make_saml_request(acs_url: acs_url, issuer: issuer) }
  
  let(:email)         { 'email@example.com' }
  
  describe "#create" do
    before do
      subject.stub(:id_resource).and_return(email)
      subject.stub(:saml_request).and_return(saml_request)
    end
    
    it "responds to a valid SAML request" do
      post :create, :SAMLrequest => saml_request
      response.body.should have_content('Click submit to continue')
    end
    
    it "generates an error with an invalid SAML request" do
      
    end
  end
end