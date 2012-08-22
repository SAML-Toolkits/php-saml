<?php
/**
 * SAMPLE Code to demonstrate how provide SAML settings.
 *
 * The settings are contained within a OneLogin_Saml_Settings object. You need to
 * provide, at a minimum, the following things:
 *
 *  - idpSingleSignOnUrl
 *    This is the URL to forward to for auth requests.
 *    It will be provided by your IdP.
 *
 *  - idpPublicCertificate
 *    This is a certificate required to authenticate your request.
 *    This certificate should be provided by your IdP.
 * 
 *  - spReturnUrl
 *    The URL that the IdP should redirect to once the authorization is complete.
 *    You must provide this, and it should point to the consume.php script or its equivalent.
 */



define('XMLSECLIBS_DIR', './../ext/xmlseclibs/');

require_once(XMLSECLIBS_DIR . 'xmlseclibs.php');


define('ONELOGIN_SAML_DIR', './../src/OneLogin/Saml/');
require_once(ONELOGIN_SAML_DIR . 'AuthRequest.php');
require_once(ONELOGIN_SAML_DIR . 'Response.php');
require_once(ONELOGIN_SAML_DIR . 'Settings.php');
require_once(ONELOGIN_SAML_DIR . 'XmlSec.php');

$settings = new OneLogin_Saml_Settings();

// When using Service Provider Initiated SSO (starting at index.php), this URL asks the IdP to authenticate the user.
$settings->idpSingleSignOnUrl = 'https://idp.junyo.com/idp/saml2/idp/SSOService.php';

// The certificate for the users account in the IdP
$settings->idpPublicCertificate = <<<CERTIFICATE
-----BEGIN CERTIFICATE-----
MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMC
Tk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYD
VQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG
9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4
MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xi
ZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2Zl
aWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5v
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LO
NoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHIS
KOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d
1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8
BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7n
bK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2Qar
Q4/67OZfHd7R+POBXhophSMv1ZOo
-----END CERTIFICATE-----
CERTIFICATE;

// The URL where to the SAML Response/SAML Assertion will be posted
$settings->spReturnUrl = 'http://localhost/php-saml/demo/consume.php';

// Name of this application
$settings->spIssuer = 'php-saml-demo';

// Tells the IdP to return the email address of the current user
$settings->requestedNameIdFormat = OneLogin_Saml_Settings::NAMEID_EMAIL_ADDRESS;

return $settings;