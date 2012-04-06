<?php

class OneLogin_Saml_ResponseTest extends PHPUnit_Framework_TestCase
{
    private $_settings;

    public function setUp()
    {
        $this->_settings = new OneLogin_Saml_Settings;
    }

    public function testReturnNameId()
    {
        $assertion = file_get_contents(TEST_ROOT . '/responses/response1.xml.base64');
        $response = new OneLogin_Saml_Response($this->_settings, $assertion);

        $this->assertEquals('support@onelogin.com', $response->getNameId());
    }

    public function testGetAttributes()
    {
        $assertion = file_get_contents(TEST_ROOT . '/responses/response1.xml.base64');
        $response = new OneLogin_Saml_Response($this->_settings, $assertion);

        $expectedAttributes = array(
            'uid' => array(
                'demo'
            ),
            'another_value' => array(
                'value'
            ),
        );
        $this->assertEquals($expectedAttributes, $response->getAttributes());

        // An assertion that has no attributes should return an empty array when asked for the attributes
        $assertion = file_get_contents(TEST_ROOT . '/responses/response2.xml.base64');
        $response = new OneLogin_Saml_Response($this->_settings, $assertion);

        $this->assertEmpty($response->getAttributes());
    }

    public function testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference()
    {
        $assertion = file_get_contents(TEST_ROOT . '/responses/wrapped_response_2.xml.base64');
        $response = new OneLogin_Saml_Response($this->_settings, $assertion);
        try {
            $nameId = $response->getNameId();
            $this->assertNotEquals('root@example.com', $nameId);
        }
        catch (Exception $e) {
            $this->assertNotEmpty($e->getMessage(), 'Trying to get NameId on an unsigned assertion fails');
        }
    }

    public function testDoesNotAllowSignatureWrappingAttack()
    {
        $assertion = file_get_contents(TEST_ROOT . '/responses/response4.xml.base64');
        $response = new OneLogin_Saml_Response($this->_settings, $assertion);

        $this->assertEquals('test@onelogin.com', $response->getNameId());
    }
}