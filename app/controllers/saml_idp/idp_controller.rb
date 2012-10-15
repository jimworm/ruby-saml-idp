# encoding: utf-8
module SamlIdp
  class IdpController < ActionController::Base
    include SamlIdp::Controller

    unloadable
    protect_from_forgery

    before_filter :validate_saml_request

    def new
      render :template => "saml_idp/idp/new"
    end

    def create
      render('saml_idp/idp/saml_post', layout: false) and return if @saml_response = encode_SAMLResponse(current_user.email, decoded_saml_request)
      render 'saml_idp/idp/new'
    end

    protected
    def saml_request
      params[:SAMLRequest] || session[:saml]
    end
    helper_method :saml_request
  
    def decoded_saml_request(saml_request)
      @decoded_saml_request ||= decode_SAMLRequest(saml_request)
    end
    helper_method :decoded_saml_request
  
    def validate_saml_request
      decoded_saml_request(saml_request)
    rescue
      render 'saml_idp/idp/error' and return
    end
  end
end
