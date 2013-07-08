<?php
/**
 * Test unit for Response messages signed as whole instead of having
 * the Assertion signed, as specified in SAML 2.0 core, par. 5.2
 */
class OneLogin_Saml_SignedResponseTest extends PHPUnit_Framework_TestCase
{
    private $_settings;

    public function setUp()
    {
        $this->_settings = new OneLogin_Saml_Settings;
    }
    
    public function testResponseSignedAssertionNot()
    {
        // The Response is signed, the Assertion is not
        $message = file_get_contents(TEST_ROOT . '/responses/open_saml_response.xml');
        $response = new OneLogin_Saml_Response($this->_settings, base64_encode($message));
        
        $this->assertEquals('someone@example.org', $response->getNameId());
    }

    public function testResponseAndAssertionSigned()
    {
        // Both the Response and the Asseretion are signed
        $message = file_get_contents(TEST_ROOT . '/responses/simple_saml_php.xml');
        $response = new OneLogin_Saml_Response($this->_settings, base64_encode($message));
        
        $this->assertEquals('someone@example.com', $response->getNameId());
    }    
}
?>
