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
  }

?>