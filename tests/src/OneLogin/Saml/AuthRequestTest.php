<?php

class OneLogin_Saml_AuthRequestTest extends PHPUnit_Framework_TestCase
{
    private $_settings;

    public function setUp()
    {
        $settings = new OneLogin_Saml_Settings;
        $settings->idpSingleSignOnUrl = 'http://stuff.com';
        $this->_settings = $settings;
    }

    public function testCreateDeflatedSAMLRequestURLParameter()
    {
        $request = new OneLogin_Saml_AuthRequest($this->_settings);
        $authUrl = $request->getRedirectUrl();
        $this->assertRegExp('#^http://stuff\.com\?SAMLRequest=#', $authUrl);

        $exploded = explode('=', $authUrl);
        $payload = urldecode($exploded[sizeof($exploded) - 1]);
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertRegExp('#^<samlp:AuthnRequest#', $inflated);
    }
}