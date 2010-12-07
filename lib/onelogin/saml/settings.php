<?php

  /**
   * Holds SAML settings for the SamlResponse and SamlAuthRequest classes.
   *
   * These settings need to be filled in by the user prior to being used.
   */
  class SamlSettings {
    /**
     * The URL to submit SAML authentication requests to.
     */
    var $idp_sso_target_url = '';

    /**
     * The x509 certificate used to authenticate the request.
     */
    var $x509certificate = '';

    /**
     * The URL where to the SAML Response/SAML Assertion will be posted.
     */
    var $assertion_consumer_service_url = '';

    /**
     * The name of the application.
     */
    var $issuer = "php-saml";

    /**
     * Specifies what format to return the authentication token, i.e, the email address.
     */
    var $name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
  }

?>