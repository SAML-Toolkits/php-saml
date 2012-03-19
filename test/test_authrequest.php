<?php
require_once 'lib/onelogin/saml/authrequest.php';
require_once 'lib/onelogin/saml/settings.php';

class AuthRequestTest extends PHPUnit_Framework_TestCase {
  private $settings;
  private $request;

  public function setUp() {
    $this->settings = new SamlSettings;
  }

  public function testCreatetheDeflatedSAMLRequestURLParameter() {
    $this->settings->idp_sso_target_url = 'http://stuff.com';
    $this->request = new SamlAuthRequest($this->settings);
    $authUrl = $this->request->create();
    $this->assertRegExp('/^http:\/\/stuff\.com\?SAMLRequest=/', $authUrl);

    $exploded = explode('=', $authUrl);
    $payload = urldecode($exploded[sizeof($exploded) - 1]);
    $decoded = base64_decode($payload);
    $inflated = gzinflate($decoded);
    $this->assertRegExp('/^<samlp:AuthnRequest/', $inflated);
  }
}
