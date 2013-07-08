<?php

class OneLogin_Saml_EncryptedResponseTest extends PHPUnit_Framework_TestCase
{
    private $_settings;

    public function setUp()
    {
        $this->_settings = new OneLogin_Saml_Settings;
        //$this->_settings->spReturnUrl = 'http://localhost:8080/php-saml-master/demo/consume.php';
        $this->_settings->spPrivateKey = file_get_contents(TEST_ROOT . '/certificates/testkey.pem');
    }
    
    public function testDecryptAssertion()
    {
        $message = file_get_contents(TEST_ROOT . '/responses/encrypted_response.xml');
        $response = new OneLogin_Saml_Response($this->_settings, base64_encode($message));
        
        $this->assertTrue($response->encrypted);
        $this->assertEquals('http://localhost:8080/php-saml-master/demo/consume.php',
                $response->getDestination());
    }

    public function testGetAttributes()
    {
        $message = file_get_contents(TEST_ROOT . '/responses/encrypted_response.xml');
        $response = new OneLogin_Saml_Response($this->_settings, base64_encode($message));

        $expectedAttributes = array(
            'urn:oid:0.9.2342.19200300.100.1.3' => array(
                'prove@csita.unige.it'
            ),
        );
        $this->assertEquals($expectedAttributes, $response->getAttributes());
    }
    
}
