<?php

/**
 * Unit tests for AuthN Request
 */
class OneLogin_Saml2_AuthnRequestTest extends PHPUnit_Framework_TestCase
{
    private $_settings;

    /**
    * Initializes the Test Suite
    */
    public function setUp()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $this->_settings = $settings;
    }

    /**
    * Tests the OneLogin_Saml2_AuthnRequest Constructor. 
    * The creation of a deflated SAML Request
    *
    * @covers OneLogin_Saml2_AuthnRequest
    */
    public function testCreateDeflatedSAMLRequestURLParameter()
    {
        $authnRequest = new OneLogin_Saml2_AuthnRequest($this->_settings, false, false);
        $parameters = array('SAMLRequest' => $authnRequest->getRequest());
        $authUrl = OneLogin_Saml2_Utils::redirect('http://idp.example.com/SSOService.php', $parameters, true);
        $this->assertRegExp('#^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=#', $authUrl);
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertRegExp('#^<samlp:AuthnRequest#', $inflated);
    }

    /**
    * Tests the OneLogin_Saml2_AuthnRequest Constructor. 
    * The creation of a deflated SAML Request
    *
    * @covers OneLogin_Saml2_AuthnRequest
    */
    public function testCreateEncSAMLRequest()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['organization'] = array (
            'es' => array (
                'name' => 'sp_prueba',
                'displayname' => 'SP prueba',
                'url' => 'http://sp.example.com'
            )
        );
        $settingsInfo['security']['wantNameIdEncrypted'] = true;

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $authnRequest = new OneLogin_Saml2_AuthnRequest($settings);
        $parameters = array('SAMLRequest' => $authnRequest->getRequest());
        $authUrl = OneLogin_Saml2_Utils::redirect('http://idp.example.com/SSOService.php', $parameters, true);
        $this->assertRegExp('#^http://idp\.example\.com\/SSOService\.php\?SAMLRequest=#', $authUrl);
        parse_str(parse_url($authUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $message = gzinflate($decoded);
        $this->assertRegExp('#^<samlp:AuthnRequest#', $message);
        $this->assertRegExp('#AssertionConsumerServiceURL="http://stuff.com/endpoints/endpoints/acs.php">#', $message);
        $this->assertRegExp('#<saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer>#', $message);
        $this->assertRegExp('#Format="urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"#', $message);
        $this->assertRegExp('#ProviderName="SP prueba"#', $message);
    }
}
