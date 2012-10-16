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
      if @saml_response = encode_SAMLResponse(id_resource, decoded_saml_request)
        render('saml_idp/idp/saml_post', layout: false)
      else
        render 'saml_idp/idp/new'
      end
    end

    protected
    def id_resource
      fail NotImplementedError
    end
    
    def saml_request
      fail NotImplementedError
    end
    helper_method :saml_request
  
    def decoded_saml_request
      @decoded_saml_request ||= decode_SAMLRequest(saml_request)
    rescue => e
      logger.warn "SAML request failed to decode: #{e.message}"
      logger.warn "Original SAML request: '#{saml_request}`"
      raise e
    end
    helper_method :decoded_saml_request
  
    def validate_saml_request
      decoded_saml_request
    rescue
      render 'saml_idp/idp/error' and return
    end
  end
end
