<?php
  // these are account wide configuration settings

  // the URL where to the SAML Response/SAML Assertion will be posted
  $const_assertion_consumer_service_url = "http://localhost/php-saml/consume.php";
  // name of this application
  $const_issuer                         = "php-saml";
  // tells the IdP to return the email address of the current user
  $const_name_identifier_format         = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

  function get_user_settings() {
    // this function should be modified to return the SAML settings for the current user

    $settings                           = new Settings();
    // when using Service Provider Initiated SSO (starting at index.php), this URL asks the IdP to authenticate the user. 
    $settings->idp_sso_target_url       = "https://app.onelogin.com/saml/signon/6171";
    // the certificate for the users account in the IdP
    $settings->x509certificate          = "-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----";

    return $settings;
  }
  
?>