<?php

/**
 * Unit tests for Response messages
 */

class OneLogin_Saml2_ResponseTest extends PHPUnit_Framework_TestCase
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
    * Tests the OneLogin_Saml2_Response Constructor. 
    *
    * @covers OneLogin_Saml2_Response
    */
    public function testConstruct()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertTrue($response instanceof OneLogin_Saml2_Response);


        $xmlEnc = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $responseEnc = new OneLogin_Saml2_Response($this->_settings, $xmlEnc);

        $this->assertTrue($responseEnc instanceof OneLogin_Saml2_Response);
    }

    public function testNamespaces()
    {
        $xml = base64_encode(file_get_contents(TEST_ROOT . '/data/responses/open_saml_response.xml'));

        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $attributes = $response->getAttributes();

        $this->assertNotEmpty($attributes);

        $this->assertEquals(array('FirstName','LastName'), array_keys($attributes));

        $this->assertEquals('Someone', $attributes['FirstName'][0]);
        $this->assertEquals('Special', $attributes['LastName'][0]);
    }

    /**
    * Tests the getNameId method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getNameId
    */
    public function testReturnNameId()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertEquals('support@onelogin.com', $response->getNameId());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $response2->getNameId());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertEquals('_68392312d490db6d355555cfbbd8ec95d746516f60', $response3->getNameId());
        
        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new OneLogin_Saml2_Response($this->_settings, $xml4);

        try {
            $nameIdData4 = $response4->getNameId();
        } catch (Exception $e) {
            $this->assertContains('Not NameID found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
    * Tests the getNameIdData method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getNameIdData
    */
    public function testGetNameIdData()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $expectedNameIdData = array (
            'Value' => 'support@onelogin.com',
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
        );
        $nameIdData = $response->getNameIdData();
        $this->assertEquals($expectedNameIdData, $nameIdData);

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $expectedNameIdData2 = array (
            'Value' => '2de11defd199f8d5bb63f9b7deb265ba5c675c10',
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified',
            'SPNameQualifier' => 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php'
        );
        $nameIdData2 = $response2->getNameIdData();
        $this->assertEquals($expectedNameIdData2, $nameIdData2);

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $expectedNameIdData3 = array (
            'Value' => '_68392312d490db6d355555cfbbd8ec95d746516f60',
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'SPNameQualifier' => 'http://stuff.com/endpoints/metadata.php'
        );
        $nameIdData3 = $response3->getNameIdData();
        $this->assertEquals($expectedNameIdData3, $nameIdData3);

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new OneLogin_Saml2_Response($this->_settings, $xml4);

        try {
            $nameIdData4 = $response4->getNameIdData();
        } catch (Exception $e) {
            $this->assertContains('Not NameID found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
    * Tests the checkStatus method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::checkStatus
    */
    public function testCheckStatus()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $response->checkStatus();

        $xmlEnc = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $responseEnc = new OneLogin_Saml2_Response($this->_settings, $xmlEnc);
        
        $response->checkStatus();

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
      
        try {
            $response2->checkStatus();
            $this->assertTrue(false);
        } catch (Exception $e) {
            $this->assertContains('The status code of the Response was not Success, was Responder', $e->getMessage());
        }

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        try {
            $response3->checkStatus();
            $this->assertTrue(false);
        } catch (Exception $e) {
            $this->assertContains('The status code of the Response was not Success, was Responder -> something_is_wrong', $e->getMessage());
        }
    }

    /**
    * Tests the getAudiences method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getAudiences
    */
    public function testGetAudiences()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertEquals(array('{audience}'), $response->getAudiences());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);

        $this->assertEquals(array('http://stuff.com/endpoints/metadata.php'), $response2->getAudiences());
    }

    /**
    * Tests the _queryAssertion and _query methods of the OneLogin_Saml2_Response
    * using the getIssuers call
    */
    public function testQueryAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertEquals(array('https://app.onelogin.com/saml/metadata/13590'), $response->getIssuers());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertEquals(array('http://idp.example.com/'), $response2->getIssuers());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response3->getIssuers());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64');
        $response4 = new OneLogin_Saml2_Response($this->_settings, $xml4);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'), $response4->getIssuers());

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64');
        $response5 = new OneLogin_Saml2_Response($this->_settings, $xml5);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response5->getIssuers());

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64');
        $response6 = new OneLogin_Saml2_Response($this->_settings, $xml6);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'), $response6->getIssuers());

        $xml7 = file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64');
        $response7 = new OneLogin_Saml2_Response($this->_settings, $xml7);
        $this->assertEquals(array('http://idp.example.com/'), $response7->getIssuers());

    }

    /**
    * Tests the getIssuers method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getIssuers
    */
    public function testGetIssuers()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertEquals(array('https://app.onelogin.com/saml/metadata/13590'), $response->getIssuers());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertEquals(array('http://idp.example.com/'), $response2->getIssuers());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response3->getIssuers());
    }




    /**
    * Tests the getSessionIndex method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getSessionIndex
    */
    public function testGetSessionIndex()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertEquals('_531c32d283bdff7e04e487bcdbc4dd8d', $response->getSessionIndex());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);

        $this->assertEquals('_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c', $response2->getSessionIndex());
    }


    /**
    * Tests the getAttributes method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getAttributes
    */
    public function testGetAttributes()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

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
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);

        $this->assertEmpty($response2->getAttributes());

        // Encrypted Attributes are not supported
        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertEmpty($response3->getAttributes());
    }

    /**
    * Tests the getNameId method of the OneLogin_Saml2_Response
    *
    * The Assertion is unsigned so the method fails
    * 
    * @covers OneLogin_Saml2_Response::getNameId
    */
    public function testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/wrapped_response_2.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        try {
            $nameId = $response->getNameId();
            $this->assertFalse($response->isValid());
            $this->assertNotEquals('root@example.com', $nameId);
        } catch (Exception $e) {
            $this->assertNotEmpty($e->getMessage(), 'Trying to get NameId on an unsigned assertion fails');
        }
    }

    /**
    * Tests the getError method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getError
    */
    public function testGetError()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertNull($response->getError());

        $this->assertFalse($response->isValid());
        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);

        $this->assertTrue($response2->isValid());
        $this->assertNull($response2->getError());
    }

    /**
    * Tests the getNameId method of the OneLogin_Saml2_Response
    *
    * Test that the SignatureWrappingAttack is not allowed
    * 
    * @covers OneLogin_Saml2_Response::getNameId
    */
    public function testDoesNotAllowSignatureWrappingAttack()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertEquals('test@onelogin.com', $response->getNameId());

        $this->assertFalse($response->isValid());

        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());
    }

    /**
    * Tests the getSessionNotOnOrAfter method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::getSessionNotOnOrAfter
    */
    public function testGetSessionNotOnOrAfter()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertEquals(1290203857, $response->getSessionNotOnOrAfter());
        
        // An assertion that do not specified Session timeout should return NULL
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertNull($response2->getSessionNotOnOrAfter());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertEquals(2696012228, $response3->getSessionNotOnOrAfter());
    }

    /**
    * Tests the validateNumAssertions method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::validateNumAssertions
    */
    public function testValidateNumAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertTrue($response->validateNumAssertions());

        $xmlMultiAssertion = file_get_contents(TEST_ROOT . '/data/responses/invalids/multiple_assertions.xml.base64');

        $response2 = new OneLogin_Saml2_Response($this->_settings, $xmlMultiAssertion);

        $this->assertFalse($response2->validateNumAssertions());
    }

    /**
    * Tests the validateTimestamps method of the OneLogin_Saml2_Response
    *
    * @covers OneLogin_Saml2_Response::validateTimestamps
    */
    public function testValidateTimestamps()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertTrue($response->validateTimestamps());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertTrue($response2->validateTimestamps());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertFalse($response3->validateTimestamps());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/not_after_failed.xml.base64');
        $response4 = new OneLogin_Saml2_Response($this->_settings, $xml4);
        $this->assertFalse($response4->validateTimestamps());

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/not_before_failed.xml.base64');
        $response5 = new OneLogin_Saml2_Response($this->_settings, $xml5);
        $this->assertFalse($response5->validateTimestamps());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid version    
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testValidateVersion()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_saml2.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Unsupported SAML version', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid no ID    
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testValidateID()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_id.xml.base64');

        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Missing ID attribute on SAML Response', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid reference
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidReference()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Reference validation failed', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case expired response
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidExpired()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('Timing issues (please check your clock settings)', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case no key
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidNoKey()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('We have no idea about the key', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid multiple assertions
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidMultipleAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/multiple_assertions.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid Encrypted Attrs
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidEncAttrs()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('There is an EncryptedAttribute in the Response and this SP not support them', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid xml
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidWrongXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $settings->setStrict(false);

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_xml.xml.base64');
        $response = new OneLogin_Saml2_Response($settings, $xml);

        $this->assertTrue($response->isValid());

        $settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($settings, $xml);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response2->getError());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new OneLogin_Saml2_Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new OneLogin_Saml2_Response($settings2, $xml);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new OneLogin_Saml2_Response($settings2, $xml);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response4->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid Destination
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidDestination()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertContains('The response was received at', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid Audience
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidAudience()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_audience.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($this->_settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertContains('is not a valid audience for this Response', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid Issuer
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidIssuer()
    {
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_assertion.xml.base64');

        $plainMessage = base64_decode($xml);
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_message.xml.base64');

        $plainMessage2 = base64_decode($xml2);
        $plainMessage2 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage2);
        $message2 = base64_encode($plainMessage2);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $response2 = new OneLogin_Saml2_Response($this->_settings, $message2);
        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());

        $this->_settings->setStrict(true);
        $response3 = new OneLogin_Saml2_Response($this->_settings, $message);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('Invalid issuer in the Assertion/Response', $response3->getError());

        $response4 = new OneLogin_Saml2_Response($this->_settings, $message2);

        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid issuer in the Assertion/Response', $response4->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid SessionIndex
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidSessionIndex()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_sessionindex.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new OneLogin_Saml2_Response($this->_settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid SubjectConfirmation
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidSubjectConfirmation()
    {
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_subjectconfirmation_method.xml.base64');
        $plainMessage = base64_decode($xml);
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_subjectconfirmation_data.xml.base64');
        $plainMessage2 = base64_decode($xml2);
        $plainMessage2 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage2);
        $message2 = base64_encode($plainMessage2);

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_inresponse.xml.base64');
        $plainMessage3 = base64_decode($xml3);
        $plainMessage3 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage3);
        $message3 = base64_encode($plainMessage3);

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_recipient.xml.base64');
        $plainMessage4 = base64_decode($xml4);
        $plainMessage4 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage4);
        $message4 = base64_encode($plainMessage4);

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_noa.xml.base64');
        $plainMessage5 = base64_decode($xml5);
        $plainMessage5 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage5);
        $message5 = base64_encode($plainMessage5);

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_subjectconfirmation_nb.xml.base64');
        $plainMessage6 = base64_decode($xml6);
        $plainMessage6 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage6);
        $message6 = base64_encode($plainMessage6);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $response2 = new OneLogin_Saml2_Response($this->_settings, $message2);
        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());

        $response3 = new OneLogin_Saml2_Response($this->_settings, $message3);
        $response3->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response4 = new OneLogin_Saml2_Response($this->_settings, $message4);
        $response3->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response5 = new OneLogin_Saml2_Response($this->_settings, $message5);
        $response5->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response6 = new OneLogin_Saml2_Response($this->_settings, $message6);
        $response6->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $this->_settings->setStrict(true);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);
        $this->assertFalse($response->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response->getError());

        $response2 = new OneLogin_Saml2_Response($this->_settings, $message2);
        $this->assertFalse($response2->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response2->getError());

        $response3 = new OneLogin_Saml2_Response($this->_settings, $message3);
        $this->assertFalse($response3->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response3->getError());

        $response4 = new OneLogin_Saml2_Response($this->_settings, $message4);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response4->getError());

        $response5 = new OneLogin_Saml2_Response($this->_settings, $message5);
        $this->assertFalse($response5->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response5->getError());

        $response6 = new OneLogin_Saml2_Response($this->_settings, $message6);

        $this->assertFalse($response6->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response6->getError());
    }

/**
    * Somtimes IdPs uses datetimes with miliseconds, this
    * test is to verify that the toolkit supports them
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testDatetimeWithMiliseconds()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response_with_miliseconds.xm.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);

        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response2 = new OneLogin_Saml2_Response($this->_settings, $message);

        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid requestID
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidRequestId()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new OneLogin_Saml2_Response($this->_settings, $message);

        $requestId = 'invalid';
        $response->isValid($requestId);
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);

        $response2 = new OneLogin_Saml2_Response($this->_settings, $message);
        $response2->isValid($requestId);
        $this->assertContains('The InResponseTo of the Response', $response2->getError());
        
        $validRequestId = '_57bcbf70-7b1f-012e-c821-782bcb13bb38';
        $response2->isValid($validRequestId);
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getError());
    }


    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid signing issues
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidSignIssues()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response = new OneLogin_Saml2_Response($settings, $message);
        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $settings2 = new OneLogin_Saml2_Settings($settingsInfo);
        $response2 = new OneLogin_Saml2_Response($settings2, $message);
        $response2->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settings3 = new OneLogin_Saml2_Settings($settingsInfo);
        $response3 = new OneLogin_Saml2_Response($settings3, $message);
        $response3->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response3->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $settings4 = new OneLogin_Saml2_Settings($settingsInfo);
        $response4 = new OneLogin_Saml2_Response($settings4, $message);

        $this->assertFalse($response4->isValid());
        $this->assertEquals('The Assertion of the Response is not signed and the SP requires it', $response4->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settingsInfo['strict'] = false;

        $settingsInfo['security']['wantMessagesSigned'] = false;
        $settings5 = new OneLogin_Saml2_Settings($settingsInfo);
        $response5 = new OneLogin_Saml2_Response($settings5, $message);
        $response5->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response5->getError());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settings6 = new OneLogin_Saml2_Settings($settingsInfo);
        $response6 = new OneLogin_Saml2_Response($settings6, $message);
        $response6->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response6->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = false;
        $settings7 = new OneLogin_Saml2_Settings($settingsInfo);
        $response7 = new OneLogin_Saml2_Response($settings7, $message);
        $response7->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response7->getError());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settings8 = new OneLogin_Saml2_Settings($settingsInfo);
        $response8 = new OneLogin_Saml2_Response($settings8, $message);

        $this->assertFalse($response8->isValid());
        $this->assertEquals('The Message of the Response is not signed and the SP requires it', $response8->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response class
    * Case Invalid Response, Invalid encryptation issues
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidEncIssues()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response = new OneLogin_Saml2_Response($settings, $message);
        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response2 = new OneLogin_Saml2_Response($settings, $message);
        $response2->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response2->getError());

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response3 = new OneLogin_Saml2_Response($settings, $message);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('The assertion of the Response is not encrypted and the SP requires it', $response3->getError());
        
        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $settingsInfo['security']['wantNameIdEncrypted'] = true;
        $settingsInfo['strict'] = false;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response4 = new OneLogin_Saml2_Response($settings, $message);
        $response4->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response4->getError());

        $settingsInfo['strict'] = true;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response5 = new OneLogin_Saml2_Response($settings, $message);
        $this->assertFalse($response5->isValid());
        $this->assertEquals('The NameID of the Response is not encrypted and the SP requires it', $response5->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid cert
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidCert()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['x509cert'] = 'NotValidCert';
        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $response = new OneLogin_Saml2_Response($settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('openssl_x509_read(): supplied parameter cannot be coerced into an X509 certificate!', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case invalid cert2
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsInValidCert2()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['x509cert'] = 'MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290 MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9 uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0 WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0 Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5 6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=';
        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $response = new OneLogin_Saml2_Response($settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Signature validation failed. SAML Response rejected', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case response with different namespace
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testNamespaceIsValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_namespaces.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case response from ADFS
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testADFSValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_adfs1.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $response->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response->getError());
    }


    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case valid response
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);

        $this->assertTrue($response->isValid());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case valid response2
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsValid2()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['certFingerprint'] = OneLogin_Saml2_Utils::calculateX509Fingerprint($settingsInfo['idp']['x509cert']);
        $settingsInfo['idp']['x509cert'] = null;

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response = new OneLogin_Saml2_Response($settings, $xml);

        $this->assertTrue($response->isValid());
    }


    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case valid encrypted assertion
    *
    * Signed data can't be modified, so Destination will always fail in strict mode
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsValidEnc()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertTrue($response2->isValid());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertTrue($response3->isValid());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = true;
        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        // In order to avoid the destination problem
        $plainMessage4 = base64_decode($xml4);
        $currentURL = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        $plainMessage4 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage4);
        $message4 = base64_encode($plainMessage4);

        $response4 = new OneLogin_Saml2_Response($settings, $message4);

        $response4->isValid();
        $this->assertContains('No Signature found. SAML Response rejected', $response4->getError());
    }

    /**
    * Tests the isValid method of the OneLogin_Saml2_Response
    * Case valid sign response / sign assertion / both signed
    *
    * Strict mode will always fail due destination problem, if we manipulate it
    * the sign will fail.
    *
    * @covers OneLogin_Saml2_Response::isValid
    */
    public function testIsValidSign()
    {

        $xml = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new OneLogin_Saml2_Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());
        
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64');
        $response2 = new OneLogin_Saml2_Response($this->_settings, $xml2);
        $this->assertTrue($response2->isValid());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64');
        $response3 = new OneLogin_Saml2_Response($this->_settings, $xml3);
        $this->assertTrue($response3->isValid());

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode($xml));
        $dom->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml4 = base64_encode($dom->saveXML());
        $response4 = new OneLogin_Saml2_Response($this->_settings, $xml4);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Reference validation failed', $response4->getError());

        $dom2 = new DOMDocument();
        $dom2->loadXML(base64_decode($xml2));
        $dom2->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml5 = base64_encode($dom2->saveXML());
        $response5 = new OneLogin_Saml2_Response($this->_settings, $xml5);
        $this->assertTrue($response5->isValid());

        $dom3 = new DOMDocument();
        $dom3->loadXML(base64_decode($xml3));
        $dom3->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml6 = base64_encode($dom3->saveXML());
        $response6 = new OneLogin_Saml2_Response($this->_settings, $xml6);
        $this->assertFalse($response6->isValid());
        $this->assertEquals('Reference validation failed', $response6->getError());
    }

    public function testIsValidSignWithEmptyReferenceURI()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_without_reference_uri.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['certFingerprint'] = "194d97e4d8c9c8cfa4b721e5ee497fd9660e5213";
        $settingsInfo['idp']['x509cert'] = null;

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $response = new OneLogin_Saml2_Response($settings, $xml);
        $this->assertTrue($response->isValid());
    }
}
