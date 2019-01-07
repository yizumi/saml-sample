require 'ruby-saml'

class SamlController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:consume]

  def index
    request = OneLogin::RubySaml::Authrequest.new
    redirect_url = request.create(saml_settings)
    redirect_to(redirect_url)
  end

  def consume
    response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], settings: saml_settings)

    if response.is_valid?
      session[:nameid] = response.nameid
      session[:attributes] = response.attributes
      @attrs = session[:attributes]
      logger.info "Successfully logged in"
      logger.info "NAMEID: #{response.nameid}"
      render json: { status: 'success', session: session }
    else
      logger.info "Response Invalid. Errors: #{response.errors}"
      @errors = response.errors
      render json: { status: 'not successful' }
    end
  end

  private

  def saml_settings
    settings = OneLogin::RubySaml::Settings.new
    settings.soft = true
    settings.issuer = "http://localhost:3000/saml/metadata"
    settings.assertion_consumer_service_url = "http://localhost:3000/saml/consume"
    settings.assertion_consumer_logout_service_url = "http://localhost:3000/saml/logout"

    settings.idp_entity_id = "https://app.onelogin.com/saml/metadata/#{app_id}"
    # settings.idp_sso_target_url = "https://app.onelogin.com/trust/saml2/http-redirect/sso/#{app_id}"
    settings.idp_sso_target_url = "https://apcandsons-secure.onelogin.com/trust/saml2/http-post/sso/854967"
    # settings.idp_slo_target_url = "https://app.onelogin.com/trust/saml2/http-redirect/slo/#{app_id}"
    settings.idp_slo_target_url = "https://apcandsons-secure.onelogin.com/trust/saml2/http-redirect/slo/854967"
    settings.idp_cert_fingerprint = "DE:30:21:00:F6:02:C1:7D:C2:3C:0B:91:7B:1D:8F:DA:D1:F2:00:1B"
    settings.idp_cert_fingerprint_algorithm = XMLSecurity::Document::SHA1

    settings.name_identifier_format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # Security section
    settings.security[:authn_requests_signed] = false
    settings.security[:logout_requests_signed] = false
    settings.security[:logout_responses_signed] = false
    settings.security[:metadata_signed] = false
    settings.security[:digest_method] = XMLSecurity::Document::SHA1
    settings.security[:signature_method] = XMLSecurity::Document::RSA_SHA256
 
    settings
  end

  def app_id
    "5b1642a9-0720-49db-8073-386eb24f205f"
  end

  def url_base
    "#{request.protocol}#{request.host_with_port}"
  end
end
