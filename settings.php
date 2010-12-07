<?php
  /**
   * SAMPLE Code to demonstrate how provide SAML settings.
   *
   * The settings are contained within a SamlSettings object. You need to
   * provide, at a minimum, the following things:
   *  - idp_sso_target_url: This is the URL to forward to for auth requests.
   *    It will be provided by your IdP.
   *  - x509certificate: This is a certificate required to authenticate your
   *    request. This certificate should be provided by your IdP.
   *  - assertion_consumer_service_url: The URL that the IdP should redirect
   *    to once the authorization is complete. You must provide this, and it
   *    should point to the consume.php script or its equivalent.
   */

  /**
   * Return a SamlSettings object with user settings.
   */
  function saml_get_settings() {
    // This function should be modified to return the SAML settings for the current user

    $settings = new SamlSettings();

    // When using Service Provider Initiated SSO (starting at index.php), this URL asks the IdP to authenticate the user.
    $settings->idp_sso_target_url             = "https://app.onelogin.com/saml/signon/6171";

    // The certificate for the users account in the IdP
    $settings->x509certificate                = <<<ENDCERTIFICATE
-----BEGIN CERTIFICATE-----
MIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD
YWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxv
Z2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMDMwOTA5NTgzNFoX
DTE1MDMwOTA5NTgzNFowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju
aWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAX
BgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ
AoGBANtmwriqGBbZy5Dwy2CmJEtHEENVPoATCZP3UDESRDQmXy9Q0Kq1lBt+KyV4
kJNHYAAQ9egLGWQ8/1atkPBye5s9fxROtf8VO3uk/x/X5VSRODIrhFISGmKUnVXa
UhLFIXkGSCAIVfoR5S2ggdfpINKUWGsWS/lEzLNYMBkURXuVAgMBAAEwAwYBAAMB
AA==
-----END CERTIFICATE-----
ENDCERTIFICATE;

    // The URL where to the SAML Response/SAML Assertion will be posted
    $settings->assertion_consumer_service_url = "http://localhost/php-saml/consume.php";

    // Name of this application
    $settings->issuer                         = "php-saml";

    // Tells the IdP to return the email address of the current user
    $settings->name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";


    return $settings;
  }

?>