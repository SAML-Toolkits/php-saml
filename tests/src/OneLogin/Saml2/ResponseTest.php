<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use DOMDocument;
use DOMXPath;
use Exception;

/**
 * Unit tests for Response messages
 */

class ResponseTest extends \PHPUnit\Framework\TestCase
{
    use LegacyEncryptionSettingsTrait;
    use EncryptedNameIdTrait;

    private $_settings;

    private $_legacySettings;

    /**
     * @before
     * Initializes the Test Suite
     */
    public function init()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $this->_settings = $settings;
        $this->_legacySettings = $this->createLegacyEncryptionSettings($settingsInfo);
    }

    /**
     * RSA-1.5 key transport is accepted by default in 3.x, so it has to be disabled explicitly
     *
     * @return Settings
     */
    private function createSettingsWithoutRSA15()
    {
        include TEST_ROOT . '/settings/settings1.php';
        $settingsInfo['security']['allowRSA15KeyTransport'] = false;

        return new Settings($settingsInfo);
    }


    /**
     * Tests the Response Constructor.
     *
     * @covers OneLogin\Saml2\Response
     */
    public function testConstruct()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertTrue($response instanceof Response);


        $xmlEnc = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $responseEnc = new Response($this->_settings, $xmlEnc);

        $this->assertTrue($responseEnc instanceof Response);
    }

    /**
     * Tests that we can retrieve the raw text of an XML SAML Response
     * without going through intermediate steps
     *
     * @covers OneLogin\Saml2\Response::getXMLDocument()
     */
    public function testGetXMLDocument()
    {
        $encodedResponse = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new Response($this->_settings, $encodedResponse);
        $responseDoc = new DOMDocument();
        $responseDoc = Utils::loadXML($responseDoc, base64_decode($encodedResponse));
        $responseParsedDoc = $response->getXMLDocument();
        $this->assertEquals($responseDoc, $responseParsedDoc);

        $encodedResponse2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $decryptedResponse2 = file_get_contents(TEST_ROOT . '/data/responses/decrypted_valid_encrypted_assertion.xml');
        $response2 = new Response($this->_settings, $encodedResponse2);
        $responseDoc2 = new DOMDocument();
        $responseDoc2 = Utils::loadXML($responseDoc2, $decryptedResponse2);
        $responseParsedDoc2 = $response2->getXMLDocument();
        $this->assertEquals($responseDoc2, $responseParsedDoc2);
    }

    /**
     * Tests that we can retrieve the ID of the Response
     *
     * @covers OneLogin\Saml2\Response::getId()
     */
    public function testGetId()
    {
        $encodedResponse = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new Response($this->_settings, $encodedResponse);
        $this->assertEquals('pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375', $response->getId());
    }

    /**
     * Tests that we can retrieve the ID of the Response
     *
     * @covers OneLogin\Saml2\Response::getAssertionId()
     */
    public function testGetAssertionId()
    {
        $encodedResponse = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new Response($this->_settings, $encodedResponse);
        $this->assertEquals('_cccd6024116641fe48e0ae2c51220d02755f96c98d', $response->getAssertionId());
    }

    /**
     * Tests that we can retrieve attributes when specific namespace
     *
     * @covers OneLogin\Saml2\Response::getAttributes()
     */
    public function testNamespaces()
    {
        $xml = base64_encode(file_get_contents(TEST_ROOT . '/data/responses/open_saml_response.xml'));

        $response = new Response($this->_settings, $xml);

        $attributes = $response->getAttributes();

        $this->assertNotEmpty($attributes);

        $this->assertEquals(array('FirstName','LastName'), array_keys($attributes));

        $this->assertEquals('Someone', $attributes['FirstName'][0]);
        $this->assertEquals('Special', $attributes['LastName'][0]);
    }

    /**
     * Tests the getNameId method of the Response
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testReturnNameId()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertEquals('support@onelogin.com', $response->getNameId());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $response2->getNameId());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals('_68392312d490db6d355555cfbbd8ec95d746516f60', $response3->getNameId());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new Response($this->_settings, $xml4);

        try {
            $nameId4 = $response4->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantNameId'] = true;

        $settings = new Settings($settingsInfo);
        $response5 = new Response($settings, $xml4);

        try {
            $nameId5 = $response5->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsInfo['security']['wantNameId'] = false;

        $settings = new Settings($settingsInfo);
        $response6 = new Response($settings, $xml4);
        $nameId6 = $response6->getNameId();
        $this->assertNull($nameId6);

        unset($settingsInfo['security']['wantNameId']);
        $settings = new Settings($settingsInfo);
        $response7 = new Response($settings, $xml4);

        try {
            $nameId7 = $response7->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/wrong_spnamequalifier.xml.base64');
        $response8 = new Response($settings, $xml5);

        $nameId8 = $response8->getNameId();
        $this->assertEquals('492882615acf31c8096b627245d76ae53036c090', $nameId8);

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_nameid.xml.base64');
        $response9 = new Response($settings, $xml6);
        $nameId9 = $response9->getNameId();
        $this->assertEmpty($nameId9);

        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);
        $response10 = new Response($settings, $xml5);
        try {
            $nameId10 = $response10->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('The SPNameQualifier value mistmatch the SP entityID value.', $e->getMessage());
        }

        $response11 = new Response($settings, $xml6);

        try {
            $nameId11 = $response11->getNameId();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('An empty NameID value found', $e->getMessage());
        }
    }

    /**
     * Tests the getNameIdFormat method of the Response
     *
     * @covers OneLogin\Saml2\Response::getNameIdFormat
     */
    public function testGetNameIdFormat()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', $response->getNameIdFormat());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', $response2->getNameIdFormat());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals('urn:oasis:names:tc:SAML:2.0:nameid-format:transient', $response3->getNameIdFormat());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new Response($this->_settings, $xml4);

        try {
            $nameId4 = $response4->getNameIdFormat();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
    * Tests the getNameIdNameQualifier method of the Response
    *
    * @covers OneLogin\Saml2\Response::getNameIdNameQualifier
    */
    public function testGetNameIdNameQualifier()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertEquals('https://test.example.com/saml/metadata', $response->getNameIdNameQualifier());
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals(null, $response2->getNameIdNameQualifier());
        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals(null, $response3->getNameIdNameQualifier());
        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        try {
            $nameId4 = $response4->getNameIdNameQualifier();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
    * Tests the getNameIdSPNameQualifier method of the Response
    *
    * @covers OneLogin\Saml2\Response::getNameIdSPNameQualifier
    */
    public function testGetNameIdSPNameQualifier()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertNull($response->getNameIdSPNameQualifier());
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals('http://stuff.com/endpoints/metadata.php', $response2->getNameIdSPNameQualifier());
        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals('http://stuff.com/endpoints/metadata.php', $response3->getNameIdSPNameQualifier());
        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        $this->assertEquals('http://stuff.com/endpoints/metadata.php', $response4->getNameIdSPNameQualifier());
        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response5 = new Response($this->_settings, $xml5);
        try {
            $nameId5 = $response5->getNameIdSPNameQualifier();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }
    }

    /**
     * Tests the getNameIdData method of the Response
     *
     * @covers OneLogin\Saml2\Response::getNameIdData
     */
    public function testGetNameIdData()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);
        $expectedNameIdData = array(
            'Value' => 'support@onelogin.com',
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'NameQualifier' => 'https://test.example.com/saml/metadata'
        );
        $nameIdData = $response->getNameIdData();
        $this->assertEquals($expectedNameIdData, $nameIdData);

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $expectedNameIdData2 = array(
            'Value' => '2de11defd199f8d5bb63f9b7deb265ba5c675c10',
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'SPNameQualifier' => 'http://stuff.com/endpoints/metadata.php'
        );
        $nameIdData2 = $response2->getNameIdData();
        $this->assertEquals($expectedNameIdData2, $nameIdData2);

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $expectedNameIdData3 = array(
            'Value' => '_68392312d490db6d355555cfbbd8ec95d746516f60',
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            'SPNameQualifier' => 'http://stuff.com/endpoints/metadata.php'
        );
        $nameIdData3 = $response3->getNameIdData();
        $this->assertEquals($expectedNameIdData3, $nameIdData3);

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_nameid.xml.base64');
        $response4 = new Response($this->_settings, $xml4);

        try {
            $nameIdData4 = $response4->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantNameId'] = true;

        $settings = new Settings($settingsInfo);
        $response5 = new Response($settings, $xml4);

        try {
            $nameIdData5 = $response5->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $settingsInfo['security']['wantNameId'] = false;

        $settings = new Settings($settingsInfo);
        $response6 = new Response($settings, $xml4);
        $nameIdData6 = $response6->getNameIdData();
        $this->assertEmpty($nameIdData6);

        unset($settingsInfo['security']['wantNameId']);
        $settings = new Settings($settingsInfo);
        $response7 = new Response($settings, $xml4);

        try {
            $nameIdData7 = $response7->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the assertion of the Response', $e->getMessage());
        }

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/wrong_spnamequalifier.xml.base64');
        $response8 = new Response($settings, $xml5);
        $nameIdData8 = $response8->getNameIdData();
        $expectedNameIdData8 = array(
            'Value' => "492882615acf31c8096b627245d76ae53036c090",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            'SPNameQualifier' => "https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php"
        );
        $this->assertEquals($expectedNameIdData8, $nameIdData8);

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_nameid.xml.base64');
        $response9 = new Response($settings, $xml6);
        $nameIdData9 = $response9->getNameIdData();
        $expectedNameIdData9 = array(
            'Value' => "",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            'SPNameQualifier' => "http://stuff.com/endpoints/metadata.php"
        );
        $this->assertEquals($expectedNameIdData9, $nameIdData9);

        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);

        $response10 = new Response($settings, $xml5);
        try {
            $nameIdData10 = $response10->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('The SPNameQualifier value mistmatch the SP entityID value.', $e->getMessage());
        }

        $response11 = new Response($settings, $xml6);
        try {
            $nameIdData11 = $response11->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('An empty NameID value found', $e->getMessage());
        }

        $xml7 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_value_nameid.xml.base64');
        $response11 = new Response($this->_settings, $xml7);
        $nameIdData12 = $response11->getNameIdData();
        $expectedNameIdData10 = array(
            'Value' => "",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        $this->assertEquals($expectedNameIdData10, $nameIdData12);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantNameId'] = true;

        $settings = new Settings($settingsInfo);
        $response12 = new Response($settings, $xml7);

        try {
            $nameIdData13 = $response12->getNameIdData();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('An empty NameID value found', $e->getMessage());
        }

        $settingsInfo['security']['wantNameId'] = false;

        $settings = new Settings($settingsInfo);
        $response13 = new Response($settings, $xml7);

        $nameIdData14 = $response13->getNameIdData();

        $expectedNameIdData11 = array(
            'Value' => "",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        $this->assertEquals($expectedNameIdData11, $nameIdData14);

        $settingsInfo['strict'] = false;
        $settingsInfo['security']['wantNameId'] = true;

        $settings = new Settings($settingsInfo);
        $response14 = new Response($settings, $xml7);

        $nameIdData15 = $response14->getNameIdData();

        $expectedNameIdData12 = array(
            'Value' => "",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        $this->assertEquals($expectedNameIdData12, $nameIdData15);

        $settingsInfo['security']['wantNameId'] = false;

        $settings = new Settings($settingsInfo);
        $response15 = new Response($settings, $xml7);

        $nameIdData16 = $response15->getNameIdData();

        $expectedNameIdData13 = array(
            'Value' => "",
            'Format' => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        $this->assertEquals($expectedNameIdData13, $nameIdData16);
    }

    /**
     * Tests the checkOneCondition method of SamlResponse
     *
     * @covers OneLogin\Saml2\Response::checkOneCondition
     */
    public function testCheckOneCondition()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_conditions.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertFalse($response->checkOneCondition());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertTrue($response2->checkOneCondition());
    }

    /**
     * Tests the checkOneAuthnStatement method of SamlResponse
     *
     * @covers OneLogin\Saml2\Response::checkOneAuthnStatement
     */
    public function testCheckOneAuthNStatement()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_authnstatement.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertFalse($response->checkOneAuthnStatement());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertTrue($response2->checkOneAuthnStatement());
    }

    /**
     * Tests the checkStatus method of the Response
     *
     * @covers OneLogin\Saml2\Response::checkStatus
     */
    public function testCheckStatus()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $response->checkStatus();

        $xmlEnc = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $responseEnc = new Response($this->_settings, $xmlEnc);

        $response->checkStatus();

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64');
        $response2 = new Response($this->_settings, $xml2);

        try {
            $response2->checkStatus();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('The status code of the Response was not Success, was Responder', $e->getMessage());
        }

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        try {
            $response3->checkStatus();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('The status code of the Response was not Success, was Responder -> something_is_wrong', $e->getMessage());
        }
    }

    /**
     * Tests the getAudiences method of the Response
     *
     * @covers OneLogin\Saml2\Response::getAudiences
     */
    public function testGetAudiences()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertEquals(array('{audience}'), $response->getAudiences());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);

        $this->assertEquals(array('http://stuff.com/endpoints/metadata.php'), $response2->getAudiences());
    }

    /**
     * Tests the _queryAssertion and _query methods of the Response
     * using the getIssuers call
     */
    public function testQueryAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/adfs_response.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertEquals(array('http://login.example.com/issuer'), $response->getIssuers());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals(array('http://idp.example.com/'), $response2->getIssuers());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response3->getIssuers());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'), $response4->getIssuers());

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64');
        $response5 = new Response($this->_settings, $xml5);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response5->getIssuers());

        $xml6 = file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64');
        $response6 = new Response($this->_settings, $xml6);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php'), $response6->getIssuers());

        $xml7 = file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64');
        $response7 = new Response($this->_settings, $xml7);
        $this->assertEquals(array('http://idp.example.com/'), $response7->getIssuers());

    }

    /**
     * Tests the getIssuers method of the Response
     *
     * @covers OneLogin\Saml2\Response::getIssuers
     */
    public function testGetIssuers()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/adfs_response.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertEquals(array('http://login.example.com/issuer'), $response->getIssuers());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEquals(array('http://idp.example.com/'), $response2->getIssuers());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response3->getIssuers());

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_issuer_response.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        $issuers = $response4->getIssuers();
        $this->assertEquals(array('http://idp.example.com/'), $response4->getIssuers());

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_issuer_assertion.xml.base64');
        $response5 = new Response($this->_settings, $xml5);
        try {
            $issuers = $response5->getIssuers();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Issuer of the Assertion not found or multiple.', $e->getMessage());
        }
    }

    /**
     * Tests the getSessionIndex method of the Response
     *
     * @covers OneLogin\Saml2\Response::getSessionIndex
     */
    public function testGetSessionIndex()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertEquals('_531c32d283bdff7e04e487bcdbc4dd8d', $response->getSessionIndex());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);

        $this->assertEquals('_7164a9a9f97828bfdb8d0ebc004a05d2e7d873f70c', $response2->getSessionIndex());
    }

    /**
     * Tests the getAttributes method of the Response
     *
     * @covers OneLogin\Saml2\Response::getAttributes
     */
    public function testGetAttributes()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

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
        $response2 = new Response($this->_settings, $xml2);

        $this->assertEmpty($response2->getAttributes());

        // Encrypted Attributes are not supported
        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEmpty($response3->getAttributes());

        // Duplicated Attribute names
        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        try {
            $attrs = $response4->getAttributes();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Found an Attribute element with duplicated Name', $e->getMessage());
        }

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['security']['allowRepeatAttributeName'] = true;
        $settings2 = new Settings($settingsInfo);
        $response5 = new Response($settings2, $xml4);
        $attrs = $response5->getAttributes();
        $this->assertEquals([0 => "test", 1 => "test2"], $attrs['uid']);
    }

    /**
     * Tests the getAttributesWithFriendlyName method of the Response
     *
     * @covers OneLogin\Saml2\Response::getAttributesWithFriendlyName
     */
    public function testGetAttributesWithFriendlyName()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response6.xml.base64');
        $response = new Response($this->_settings, $xml);
        $expectedAttributes = array(
            'uid' => array(
                'demo'
            ),
            'givenName' => array(
                'value'
            ),
        );
        $this->assertEquals($expectedAttributes, $response->getAttributesWithFriendlyName());
        // An assertion that has no attributes should return an empty array when asked for the attributes
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertEmpty($response2->getAttributesWithFriendlyName());
        // Encrypted Attributes are not supported
        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEmpty($response3->getAttributesWithFriendlyName());
        // Duplicated Attribute names
        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes_with_friendly_names.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        try {
            $attrs = $response4->getAttributesWithFriendlyName();
            $this->fail('OneLogin\Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('Found an Attribute element with duplicated FriendlyName', $e->getMessage());
        }
    }

    /**
     * Tests the getNameId method of the Response
     *
     * The Assertion is unsigned, the response is invalid but is able to retrieve the NameID
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testOnlyRetrieveAssertionWithIDThatMatchesSignatureReference()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/wrapped_response_2.xml.base64');
        $response = new Response($this->_settings, $xml);

        $nameId = $response->getNameId();
        $this->assertFalse($response->isValid());
        $this->assertEquals('root@example.com', $nameId);
    }

    /**
     * Tests the getError method of the Response
     *
     * @covers OneLogin\Saml2\Response::getError
     */
    public function testGetError()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertNull($response->getErrorException());

        $this->assertFalse($response->isValid());
        $errorException = $response->getErrorException();
        $this->assertEquals('SAML Response must contain 1 assertion', $errorException->getMessage());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response2 = new Response($this->_settings, $xml2);

        $this->assertTrue($response2->isValid());
        $this->assertNull($response2->getErrorException());
    }

    /**
     * Tests the getErrorException method of the Response
     *
     * @covers OneLogin\Saml2\Response::getErrorException
     */
    public function testGetErrorException()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertNull($response->getError());

        $this->assertFalse($response->isValid());
        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response2 = new Response($this->_settings, $xml2);

        $this->assertTrue($response2->isValid());
        $this->assertNull($response2->getError());
    }

    /**
     * Tests the getNameId method of the Response
     *
     * Test that the SignatureWrappingAttack is not allowed
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testDoesNotAllowSignatureWrappingAttack()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response4.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertEquals('test@onelogin.com', $response->getNameId());

        $this->assertFalse($response->isValid());

        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());
    }

    public function testDoesNotAllowSignatureWrappingAttack2()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        unset($settingsInfo['idp']['x509cert']);
        $settingsInfo['strict'] = false;
        $settingsInfo['idp']['certFingerprint'] = "385b1eec71143f00db6af936e2ea12a28771d72c";
        $settingsInfo['sp']['privateKey'] = 'MIICXAIBAAKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABAoGBALGR6bRBit+yV5TUU3MZSrf8WQSLWDLgs/33FQSAEYSib4+DJke2lKbI6jkGUoSJgFUXFbaQLtMY2+3VDsMKPBdAge9gIdvbkC4yoKjLGm/FBDOxxZcfLpR+9OPqU3qM9D0CNuliBWI7Je+p/zs09HIYucpDXy9E18KA1KNF6rfhAkEA9KoNam6wAKnmvMzz31ws3RuIOUeo2rx6aaVY95+P9tTxd6U+pNkwxy1aCGP+InVSwlYNA1aQ4Axi/GdMIWMkxwJBAPO1CP7cQNZQmu7yusY+GUObDII5YK9WLaY4RAicn5378crPBFxvUkqf9G6FHo7u88iTCIp+vwa3Hn9Tumg3iP0CQQDgUXWBasCVqzCxU5wY4tMDWjXYhpoLCpmVeRML3dDJt004rFm2HKe7Rhpw7PTZNQZOxUSjFeA4e0LaNf838UWLAkB8QfbHM3ffjhOg96PhhjINdVWoZCb230LBOHj/xxPfUmFTHcBEfQIBSJMxcrBFAnLL9qPpMXymqOFk3ETz9DTlAj8E0qGbp78aVbTOtuwEwNJII+RPw+Zkc+lKR+yaWkAzfIXw527NPHH3+rnBG72wyZr9ud4LAum9jh+5No1LQpk=';
        $settingsInfo['sp']['x509cert'] = 'MIICGzCCAYQCCQCNNcQXom32VDANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJVUzELMAkGA1UECBMCSU4xFTATBgNVBAcTDEluZGlhbmFwb2xpczERMA8GA1UEChMIT25lTG9naW4xDDAKBgNVBAsTA0VuZzAeFw0xNDA0MjMxODQxMDFaFw0xNTA0MjMxODQxMDFaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTjEVMBMGA1UEBxMMSW5kaWFuYXBvbGlzMREwDwYDVQQKEwhPbmVMb2dpbjEMMAoGA1UECxMDRW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBALM2vGCiQ/vm+a6v40+VX2zdqHA2Q/1vF1ibQzJ54MJCOVWvs+vQXfZFhdm0OPM2IrDU7oqvKPqP6xOAeJK6H0yP7M4YL3fatSvIYmmfyXC9kt3Svz/NyrHzPhUnJ0ye/sUSXxnzQxwcm/9PwAqrQaA3QpQkH57ybF/OoryPe+2h';

        $settings = new Settings($settingsInfo);

        $xml = file_get_contents(TEST_ROOT . '/data/responses/wrapped_response_3.xml.base64');
        try {
            $response = new Response($settings, $xml);
            $valid = $response->isValid();
            $this->assertFalse($valid);
            $this->assertEquals('Found an invalid Signed Element. SAML Response rejected', $response->getError());
        } catch (Exception $e) {
            $this->assertEquals('DOMDocument::loadXML(): Namespace prefix saml on Assertion is not defined in Entity, line: 1', $e->getMessage());
        }
    }

    /**
     * Tests the getNameId and getAttributes methods of the
     * Response
     *
     * Test that the node text with comment attack (VU#475445)
     * is not allowed
     *
     * @covers OneLogin\Saml2\Response::getNameId
     * @covers OneLogin\Saml2\Response::getAttributes
     */
    public function testNodeTextAttack()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_node_text_attack.xml.base64');
        $response = new Response($this->_settings, $xml);
        $nameId = $response->getNameId();
        $attributes = $response->getAttributes();
        $this->assertEquals("support@onelogin.com", $nameId);
        $this->assertEquals("smith", $attributes['surname'][0]);
    }

    /**
     * Tests the getSessionNotOnOrAfter method of the Response
     *
     * @covers OneLogin\Saml2\Response::getSessionNotOnOrAfter
     */
    public function testGetSessionNotOnOrAfter()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertEquals(1290203857, $response->getSessionNotOnOrAfter());

        // An assertion that do not specified Session timeout should return NULL
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertNull($response2->getSessionNotOnOrAfter());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertEquals(2696012228, $response3->getSessionNotOnOrAfter());
    }

    /**
     * Tests the validateNumAssertions method of the Response
     *
     * @covers OneLogin\Saml2\Response::validateNumAssertions
     */
    public function testValidateNumAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertTrue($response->validateNumAssertions());

        $xmlMultiAssertion = file_get_contents(TEST_ROOT . '/data/responses/invalids/multiple_assertions.xml.base64');

        $response2 = new Response($this->_settings, $xmlMultiAssertion);

        $this->assertFalse($response2->validateNumAssertions());
    }

    /**
     * Tests the validateTimestamps method of the Response
     *
     * @covers OneLogin\Saml2\Response::validateTimestamps
     */
    public function testValidateTimestamps()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertTrue($response->validateTimestamps());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertTrue($response2->validateTimestamps());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        try {
            $response3->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertEquals($e->getMessage(), 'Could not validate timestamp: expired. Check system clock.');
        }

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/not_after_failed.xml.base64');
        $response4 = new Response($this->_settings, $xml4);
        try {
            $response4->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertEquals($e->getMessage(), 'Could not validate timestamp: expired. Check system clock.');
        }

        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/not_before_failed.xml.base64');
        $response5 = new Response($this->_settings, $xml5);
        try {
            $response5->validateTimestamps();
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertEquals($e->getMessage(), 'Could not validate timestamp: not yet valid. Check system clock.');
        }
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid version
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testValidateVersion()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_saml2.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Unsupported SAML version', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid no ID
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testValidateID()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_id.xml.base64');

        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Missing ID attribute on SAML Response', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid reference
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidReference()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Reference validation failed', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case expired response
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidExpired()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/expired_response.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('Could not validate timestamp: expired. Check system clock.', $response2->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case no key
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidNoKey()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('We have no idea about the key', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid multiple assertions
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidMultipleAssertions()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/multiple_assertions.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('SAML Response must contain 1 assertion', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid Encrypted Attrs
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidEncAttrs()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('There is an EncryptedAttribute in the Response and this SP not support them', $response2->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid xml
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidWrongXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_xml.xml.base64');
        $response = new Response($settings, $xml);

        $this->assertTrue($response->isValid());

        $settings->setStrict(true);
        $response2 = new Response($settings, $xml);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response2->getError());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new Response($settings2, $xml);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new Response($settings2, $xml);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid SAML Response. Not match the saml-schema-protocol-2.0.xsd', $response4->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid Destination
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidDestination()
    {
        $_SERVER['HTTP_HOST'] = 'stuff.com';
        $_SERVER['HTTPS'] = 'https';
        $_SERVER['REQUEST_URI'] = '/endpoints/endpoints/acs.php';

        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $response = new Response($this->_settings, $xml);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new Response($this->_settings, $xml);

        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('The response was received at', $response2->getError());

        // Empty Destination
        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/empty_destination.xml.base64');
        $response3 = new Response($this->_settings, $xml2);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('The response has an empty Destination value', $response3->getError());

        include TEST_ROOT .'/settings/settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['relaxDestinationValidation'] = true;
        $settings = new Settings($settingsInfo);
        $response4 = new Response($settings, $xml2);
        $this->assertTrue($response4->isValid());

        // Destination strict match
        $xml5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_strict_destination.xml.base64');
        $response5 = new Response($settings, $xml5);
        $this->assertTrue($response5->isValid());
        $settingsInfo['security']['destinationStrictlyMatches'] = true;
        $settings2 = new Settings($settingsInfo);
        $response6 = new Response($settings2, $xml5);
        $this->assertFalse($response6->isValid());
        $this->assertStringContainsString('The response was received at', $response6->getError());
        unset($settingsInfo['strict']);
        unset($settingsInfo['security']['destinationStrictlyMatches']);
        unset($_SERVER['HTTP_HOST']);
        unset($_SERVER['HTTPS']);
        unset($_SERVER['REQUEST_URI']);
    }

    /**
     * Tests the isValid method of the Response class
     * Case the Destination has the default port (not written) and the port of the SP is set as an integer
     * or as a string: it is the same URL, the port is not added to the URL where the response was received
     * (#661)
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testDestinationWithAPortOfAnyType()
    {
        $destination = 'https://example.test/admin/saml/acs';
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64'));
        $xml = preg_replace('/Destination="[^"]*"/', 'Destination="' . $destination . '"', $xml, 1, $count);
        $this->assertEquals(1, $count);
        $xml = base64_encode($xml);

        $this->_settings->setStrict(true);
        $_SERVER['REQUEST_URI'] = '/admin/saml/acs';
        Utils::setSelfProtocol('https');
        Utils::setSelfHost('example.test');

        try {
            foreach (array(443, '443') as $port) {
                Utils::setSelfPort($port);
                $response = new Response($this->_settings, $xml);
                $response->isValid();
                $this->assertStringNotContainsString('The response was received at', (string) $response->getError(), var_export($port, true));
            }

            // Another port is another destination
            foreach (array(8443, '8443') as $port) {
                Utils::setSelfPort($port);
                $response = new Response($this->_settings, $xml);
                $this->assertFalse($response->isValid());
                $this->assertEquals("The response was received at https://example.test:8443/admin/saml/acs instead of $destination", $response->getError());
            }
        } finally {
            Utils::setBaseURL(null);
            unset($_SERVER['REQUEST_URI']);
        }
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid Audience
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidAudience()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_audience.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new Response($this->_settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertSame('Invalid audience for this Response (expected \'http://stuff.com/endpoints/metadata.php\', got \'http://invalid.audience.com\')', $response2->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid Issuer
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidIssuer()
    {
        $currentURL = Utils::getSelfURLNoQuery();

        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_assertion.xml.base64');

        $plainMessage = base64_decode($xml);
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_issuer_message.xml.base64');

        $plainMessage2 = base64_decode($xml2);
        $plainMessage2 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage2);
        $message2 = base64_encode($plainMessage2);

        $response = new Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $response2 = new Response($this->_settings, $message2);
        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());

        $this->_settings->setStrict(true);
        $response3 = new Response($this->_settings, $message);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('Invalid issuer in the Assertion/Response (expected \'http://idp.example.com/\', got \'http://invalid.issuer.example.com/\')', $response3->getError());

        $response4 = new Response($this->_settings, $message2);

        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid issuer in the Assertion/Response (expected \'http://idp.example.com/\', got \'http://invalid.isser.example.com/\')', $response4->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid SessionIndex
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSessionIndex()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_sessionindex.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);
        $response2 = new Response($this->_settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('The attributes have expired, based on the SessionNotOnOrAfter of the AttributeStatement of this Response', $response2->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid SubjectConfirmation
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSubjectConfirmation()
    {
        $currentURL = Utils::getSelfURLNoQuery();

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

        $response = new Response($this->_settings, $message);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $response2 = new Response($this->_settings, $message2);
        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());

        $response3 = new Response($this->_settings, $message3);
        $response3->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response4 = new Response($this->_settings, $message4);
        $response3->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response5 = new Response($this->_settings, $message5);
        $response5->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $response6 = new Response($this->_settings, $message6);
        $response6->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response3->getError());

        $this->_settings->setStrict(true);

        $response = new Response($this->_settings, $message);
        $this->assertFalse($response->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response->getError());

        $response2 = new Response($this->_settings, $message2);
        $this->assertFalse($response2->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response2->getError());

        $response3 = new Response($this->_settings, $message3);
        $this->assertFalse($response3->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response3->getError());

        $response4 = new Response($this->_settings, $message4);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response4->getError());

        $response5 = new Response($this->_settings, $message5);
        $this->assertFalse($response5->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response5->getError());

        $response6 = new Response($this->_settings, $message6);

        $this->assertFalse($response6->isValid());
        $this->assertEquals('A valid SubjectConfirmation was not found on this Response', $response6->getError());
    }

    /**
     * Sometimes IdPs uses datetimes with milliseconds, this
     * test is to verify that the toolkit supports them
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testDatetimeWithMiliseconds()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response_with_miliseconds.xm.base64');
        $response = new Response($this->_settings, $xml);
        $response->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);

        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response2 = new Response($this->_settings, $message);

        $response2->isValid();
        $this->assertEquals('No Signature found. SAML Response rejected', $response2->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid requestID
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidRequestId()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $response = new Response($this->_settings, $message);

        $requestId = 'invalid';
        $response->isValid($requestId);
        $this->assertEquals('No Signature found. SAML Response rejected', $response->getError());

        $this->_settings->setStrict(true);

        $response2 = new Response($this->_settings, $message);
        $response2->isValid($requestId);
        $this->assertStringContainsString('The InResponseTo of the Response', $response2->getError());

        $validRequestId = '_57bcbf70-7b1f-012e-c821-782bcb13bb38';
        $response2->isValid($validRequestId);
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response2->getError());
    }

    /**
    * Tests the isValid method of the Response class
    * Case Invalid Response, Unexpected InResponseTo
    *
    * @covers OneLogin\Saml2\Response::isValid
    */
    public function testIsInValidUnexpectedInResponseTo()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['security']['rejectUnsolicitedResponsesWithInResponseTo'] = true;
        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);
        $response = new Response($settings, $message);
        $inResponseTo = "_57bcbf70-7b1f-012e-c821-782bcb13bb38";
        $response->isValid();
        $this->assertEquals('The Response has an InResponseTo attribute: '.$inResponseTo.' while no InResponseTo was expected', $response->getError());
        $response->isValid($inResponseTo);
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());
    }
    /**
    * Tests the isValid method of the Response class
    * Case Invalid Response, No InResponseTo
    *
    * @covers OneLogin\Saml2\Response::isValid
    */
    public function testIsInValidNoInResponseTo()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/invalids/invalid_unpaired_inresponsesto.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['security']['rejectUnsolicitedResponsesWithInResponseTo'] = true;
        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);

        $response = new Response($settings, $message);

        $inResponseTo = "_57bcbf70-7b1f-012e-c821-782bcb13bb38";

        $response->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());

        $response->isValid($inResponseTo);
        $this->assertEquals('No InResponseTo at the Response, but it was provided the requestId related to the AuthNRequest sent by the SP: '.$inResponseTo, $response->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid signing issues
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidSignIssues()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settings = new Settings($settingsInfo);
        $response = new Response($settings, $message);
        $response->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $settings2 = new Settings($settingsInfo);
        $response2 = new Response($settings2, $message);
        $response2->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response2->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settings3 = new Settings($settingsInfo);
        $response3 = new Response($settings3, $message);
        $response3->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response3->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        $settings4 = new Settings($settingsInfo);
        $response4 = new Response($settings4, $message);

        $this->assertFalse($response4->isValid());
        $this->assertEquals('The Assertion of the Response is not signed and the SP requires it', $response4->getError());

        $settingsInfo['security']['wantAssertionsSigned'] = false;
        $settingsInfo['strict'] = false;

        $settingsInfo['security']['wantMessagesSigned'] = false;
        $settings5 = new Settings($settingsInfo);
        $response5 = new Response($settings5, $message);
        $response5->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response5->getError());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settings6 = new Settings($settingsInfo);
        $response6 = new Response($settings6, $message);
        $response6->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response6->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = false;
        $settings7 = new Settings($settingsInfo);
        $response7 = new Response($settings7, $message);
        $response7->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response7->getError());

        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settings8 = new Settings($settingsInfo);
        $response8 = new Response($settings8, $message);

        $this->assertFalse($response8->isValid());
        $this->assertEquals('The Message of the Response is not signed and the SP requires it', $response8->getError());
    }

    /**
     * Tests the isValid method of the Response class
     * Case Invalid Response, Invalid encryptation issues
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidEncIssues()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');
        $plainMessage = base64_decode($xml);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);
        $message = base64_encode($plainMessage);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $settings = new Settings($settingsInfo);
        $response = new Response($settings, $message);
        $response->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());

        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $settings = new Settings($settingsInfo);
        $response2 = new Response($settings, $message);
        $response2->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response2->getError());

        $settingsInfo['security']['wantAssertionsEncrypted'] = true;
        $settings = new Settings($settingsInfo);
        $response3 = new Response($settings, $message);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('The assertion of the Response is not encrypted and the SP requires it', $response3->getError());

        $settingsInfo['security']['wantAssertionsEncrypted'] = false;
        $settingsInfo['security']['wantNameIdEncrypted'] = true;
        $settingsInfo['strict'] = false;
        $settings = new Settings($settingsInfo);
        $response4 = new Response($settings, $message);
        $response4->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response4->getError());

        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);
        $response5 = new Response($settings, $message);
        $this->assertFalse($response5->isValid());
        $this->assertEquals('The NameID of the Response is not encrypted and the SP requires it', $response5->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid cert
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidCert()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['x509cert'] = 'NotValidCert';
        $settings = new Settings($settingsInfo);

        $response = new Response($settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('openssl_x509_read(): supplied parameter cannot be coerced into an X509 certificate!', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case invalid cert2
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsInValidCert2()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['idp']['x509cert'] = 'MIIENjCCAx6gAwIBAgIBATANBgkqhkiG9w0BAQUFADBvMQswCQYDVQQGEwJTRTEU MBIGA1UEChMLQWRkVHJ1c3QgQUIxJjAkBgNVBAsTHUFkZFRydXN0IEV4dGVybmFs IFRUUCBOZXR3b3JrMSIwIAYDVQQDExlBZGRUcnVzdCBFeHRlcm5hbCBDQSBSb290 MB4XDTAwMDUzMDEwNDgzOFoXDTIwMDUzMDEwNDgzOFowbzELMAkGA1UEBhMCU0Ux FDASBgNVBAoTC0FkZFRydXN0IEFCMSYwJAYDVQQLEx1BZGRUcnVzdCBFeHRlcm5h bCBUVFAgTmV0d29yazEiMCAGA1UEAxMZQWRkVHJ1c3QgRXh0ZXJuYWwgQ0EgUm9v dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALf3GjPm8gAELTngTlvt H7xsD821+iO2zt6bETOXpClMfZOfvUq8k+0DGuOPz+VtUFrWlymUWoCwSXrbLpX9 uMq/NzgtHj6RQa1wVsfwTz/oMp50ysiQVOnGXw94nZpAPA6sYapeFI+eh6FqUNzX mk6vBbOmcZSccbNQYArHE504B4YCqOmoaSYYkKtMsE8jqzpPhNjfzp/haW+710LX a0Tkx63ubUFfclpxCDezeWWkWaCUN/cALw3CknLa0Dhy2xSoRcRdKn23tNbE7qzN E0S3ySvdQwAl+mG5aWpYIxG3pzOPVnVZ9c0p10a3CitlttNCbxWyuHv77+ldU9U0 WicCAwEAAaOB3DCB2TAdBgNVHQ4EFgQUrb2YejS0Jvf6xCZU7wO94CTLVBowCwYD VR0PBAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgZkGA1UdIwSBkTCBjoAUrb2YejS0 Jvf6xCZU7wO94CTLVBqhc6RxMG8xCzAJBgNVBAYTAlNFMRQwEgYDVQQKEwtBZGRU cnVzdCBBQjEmMCQGA1UECxMdQWRkVHJ1c3QgRXh0ZXJuYWwgVFRQIE5ldHdvcmsx IjAgBgNVBAMTGUFkZFRydXN0IEV4dGVybmFsIENBIFJvb3SCAQEwDQYJKoZIhvcN AQEFBQADggEBALCb4IUlwtYj4g+WBpKdQZic2YR5gdkeWxQHIzZlj7DYd7usQWxH YINRsPkyPef89iYTx4AWpb9a/IfPeHmJIZriTAcKhjW88t5RxNKWt9x+Tu5w/Rw5 6wwCURQtjr0W4MHfRnXnJK3s9EK0hZNwEGe6nQY1ShjTK3rMUUKhemPR5ruhxSvC Nr4TDea9Y355e6cJDUCrat2PisP29owaQgVR1EX1n6diIWgVIEM8med8vSTYqZEX c4g/VhsxOBi0cQ+azcgOno4uG+GMmIPLHzHxREzGBHNJdmAPx/i9F4BrLunMTA5a mnkPIAou1Z5jJh5VkpTYghdae9C8x49OhgQ=';
        $settings = new Settings($settingsInfo);

        $response = new Response($settings, $xml);

        $this->assertFalse($response->isValid());
        $this->assertEquals('Signature validation failed. SAML Response rejected', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case response with different namespace
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testNamespaceIsValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_namespaces.xml.base64');
        $response = new Response($this->_settings, $xml);

        $response->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case response from ADFS
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testADFSValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_adfs1.xml.base64');
        $response = new Response($this->_settings, $xml);

        $response->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case valid response
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValid()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $response = new Response($this->_settings, $xml);

        $this->assertTrue($response->isValid());
    }

    /**
     * Tests the isValid method of the Response
     * Case valid response2
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValid2()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $cert = Utils::formatCert($settingsInfo['idp']['x509cert']);
        $settingsInfo['idp']['certFingerprint'] = Utils::calculateX509Fingerprint($cert);
        $settingsInfo['idp']['x509cert'] = null;

        $settings = new Settings($settingsInfo);
        $response = new Response($settings, $xml);

        $this->assertTrue($response->isValid());
    }

    /**
     * Tests the isValid method of the Response
     * Case: the IdP is identified by its fingerprint and the Signature has no KeyInfo. The
     * KeyInfo is not signed, so anybody can remove it from a valid response: there is no
     * certificate to compare with the fingerprint and the response is invalid.
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidFingerprintWithoutKeyInfo()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $cert = Utils::formatCert($settingsInfo['idp']['x509cert']);

        $fingerprintInfo = $settingsInfo;
        $fingerprintInfo['idp']['certFingerprint'] = Utils::calculateX509Fingerprint($cert);
        $fingerprintInfo['idp']['x509cert'] = null;

        // The KeyInfo of the Signature is not covered by the signature of the other element in a double signed
        // response, so only the responses with one Signature are used
        foreach (array('signed_message_response', 'signed_assertion_response') as $name) {
            $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/' . $name . '.xml.base64'));

            // Control: the fingerprint of the certificate in the KeyInfo is valid
            $response = new Response(new Settings($fingerprintInfo), base64_encode($xml));
            $this->assertTrue($response->isValid(), $name);

            $dom = new DOMDocument();
            $dom->loadXML($xml);
            $keyInfos = $dom->getElementsByTagNameNS(Constants::NS_DS, 'KeyInfo');
            $this->assertEquals(1, $keyInfos->length, $name);
            $keyInfos->item(0)->parentNode->removeChild($keyInfos->item(0));
            $withoutKeyInfo = base64_encode($dom->saveXML());

            // With the fingerprint the response is rejected (not because of a PHP error: with the
            // assertions disabled the code that was fixed only emitted a deprecation, that isValid reports as its error)
            $response = new Response(new Settings($fingerprintInfo), $withoutKeyInfo);
            $toException = function ($severity, $message, $file, $line) {
                throw new \ErrorException($message, 0, $severity, $file, $line);
            };
            set_error_handler($toException);
            try {
                $valid = $response->isValid();
            } finally {
                restore_error_handler();
            }
            $this->assertFalse($valid, $name);
            $this->assertEquals('Signature validation failed. SAML Response rejected', $response->getError(), $name);

            // The signature is still valid for the certificate
            $response = new Response(new Settings($settingsInfo), $withoutKeyInfo);
            $this->assertTrue($response->isValid(), $name);
        }
    }

    /**
     * Tests the isValid method of the Response
     * Case valid encrypted assertion
     *
     * Signed data can't be modified, so Destination will always fail in strict mode
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidEnc()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/responses/double_signed_encrypted_assertion.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/signed_encrypted_assertion.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertTrue($response2->isValid());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertTrue($response3->isValid());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = true;
        $settings = new Settings($settingsInfo);

        $xml4 = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        // In order to avoid the destination problem
        $plainMessage4 = base64_decode($xml4);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage4 = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage4);
        $message4 = base64_encode($plainMessage4);

        $response4 = new Response($settings, $message4);

        $response4->isValid();
        $this->assertStringContainsString('No Signature found. SAML Response rejected', $response4->getError());
    }

    /**
     * Tests the isValid method of the Response
     * Case valid sign response / sign assertion / both signed
     *
     * Strict mode will always fail due destination problem, if we manipulate it
     * the sign will fail.
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidSign()
    {

        $xml = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());

        $xml2 = file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64');
        $response2 = new Response($this->_settings, $xml2);
        $this->assertTrue($response2->isValid());

        $xml3 = file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64');
        $response3 = new Response($this->_settings, $xml3);
        $this->assertTrue($response3->isValid());

        $dom = new DOMDocument();
        $dom->loadXML(base64_decode($xml));
        $dom->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml4 = base64_encode($dom->saveXML());
        $response4 = new Response($this->_settings, $xml4);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Reference validation failed', $response4->getError());

        $dom2 = new DOMDocument();
        $dom2->loadXML(base64_decode($xml2));
        $dom2->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml5 = base64_encode($dom2->saveXML());
        $response5 = new Response($this->_settings, $xml5);
        $this->assertTrue($response5->isValid());

        $dom3 = new DOMDocument();
        $dom3->loadXML(base64_decode($xml3));
        $dom3->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $xml6 = base64_encode($dom3->saveXML());
        $response6 = new Response($this->_settings, $xml6);
        $this->assertFalse($response6->isValid());
        $this->assertEquals('Reference validation failed', $response6->getError());
    }

    public function testIsValidSignWithEmptyReferenceURI()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_without_reference_uri.xml.base64');

        $settingsInfo['idp']['x509cert'] = 'MIICGzCCAYQCCQCNNcQXom32VDANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJVUzELMAkGA1UECBMCSU4xFTATBgNVBAcTDEluZGlhbmFwb2xpczERMA8GA1UEChMIT25lTG9naW4xDDAKBgNVBAsTA0VuZzAeFw0xNDA0MjMxODQxMDFaFw0xNTA0MjMxODQxMDFaMFIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTjEVMBMGA1UEBxMMSW5kaWFuYXBvbGlzMREwDwYDVQQKEwhPbmVMb2dpbjEMMAoGA1UECxMDRW5nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDo6m+QZvYQ/xL0ElLgupK1QDcYL4f5PckwsNgS9pUvV7fzTqCHk8ThLxTk42MQ2McJsOeUJVP728KhymjFCqxgP4VuwRk9rpAl0+mhy6MPdyjyA6G14jrDWS65ysLchK4t/vwpEDz0SQlEoG1kMzllSm7zZS3XregA7DjNaUYQqwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBALM2vGCiQ/vm+a6v40+VX2zdqHA2Q/1vF1ibQzJ54MJCOVWvs+vQXfZFhdm0OPM2IrDU7oqvKPqP6xOAeJK6H0yP7M4YL3fatSvIYmmfyXC9kt3Svz/NyrHzPhUnJ0ye/sUSXxnzQxwcm/9PwAqrQaA3QpQkH57ybF/OoryPe+2h';
        $settings = new Settings($settingsInfo);
        $response = new Response($settings, $xml);
        $this->assertTrue($response->isValid());
        $attributes = $response->getAttributes();
        $this->assertTrue(!empty($attributes));
        $this->assertEquals('saml@user.com', $attributes['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'][0]);
    }

    /**
     * Tests the isValid method of the Response
     * Case: Using x509certMulti
     *
     * @covers OneLogin\Saml2\Response::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';

        $settings = new Settings($settingsInfo);

        $xml = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = new Response($settings, $xml);
        $this->assertTrue($response->isValid());
    }

    public function testCanGetEncryptedNameIdInEncryptedAssertion()
    {
        if (PHP_VERSION_ID >= 70100) { // PHP 7.1.0 is required to use AES GCM algorithms
            $xml = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid_encrypted_assertion.xml.base64');
            $response = new Response($this->_settings, $xml);
            $this->assertTrue($response->isValid());
            $this->assertSame('user@example.com', $response->getNameId());
        }

        $xml = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid_encrypted_assertion2.xml.base64');
        $response = new Response($this->_settings, $xml);
        $this->assertTrue($response->isValid());
        $this->assertSame('492882615acf31c8096b627245d76ae53036c090', $response->getNameId());
    }

    /**
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testEncryptedNameIdKeyTransport()
    {
        $expectedNameId = '2de11defd199f8d5bb63f9b7deb265ba5c675c10';

        $oaepXml = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid_oaep.xml.base64');
        $oaepResponse = new Response($this->_settings, $oaepXml);
        $this->assertEquals($expectedNameId, $oaepResponse->getNameId());

        $rsa15Xml = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64');
        $legacyResponse = new Response($this->_legacySettings, $rsa15Xml);
        $this->assertEquals($expectedNameId, $legacyResponse->getNameId());

        try {
            $blockedResponse = new Response($this->createSettingsWithoutRSA15(), $rsa15Xml);
            $blockedResponse->getNameId();
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Unsupported or not allowed key transport algorithm', $e->getMessage());
        }
    }

    /**
     * CBC data encryption is accepted by default and rejected when allowCBCEncryption is false
     *
     * @covers OneLogin\Saml2\Response::getNameId
     * @covers OneLogin\Saml2\Response::decryptAssertion
     */
    public function testAllowCBCEncryption()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['security']['allowCBCEncryption'] = false;
        $gcmOnlySettings = new Settings($settingsInfo);
        $gcmOnlyLegacySettings = $this->createLegacyEncryptionSettings($settingsInfo);

        // aes128-cbc + rsa-oaep-mgf1p in an EncryptedID
        $cbcXml = file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid_oaep.xml.base64');
        $response = new Response($this->_settings, $cbcXml);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $response->getNameId());

        try {
            $blockedResponse = new Response($gcmOnlySettings, $cbcXml);
            $blockedResponse->getNameId();
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Unsupported or not allowed data encryption algorithm', $e->getMessage());
        }

        // aes128-cbc in an EncryptedAssertion, rejected while constructing the Response
        $cbcAssertionXml = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $response = new Response($this->_legacySettings, $cbcAssertionXml);
        $this->assertNotEmpty($response->getNameId());

        try {
            new Response($gcmOnlyLegacySettings, $cbcAssertionXml);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Unsupported or not allowed data encryption algorithm', $e->getMessage());
        }

        // AES-GCM is still accepted
        $gcmXml = $this->buildResponseWithEncryptedAssertion($this->buildEncryptedNameId());
        $response = new Response($gcmOnlySettings, $gcmXml);
        $this->assertEquals('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', $response->getNameId());
    }

    /**
     * When signed messages are required, the signature of the Response is verified
     * before decrypting the EncryptedAssertion
     *
     * @covers OneLogin\Saml2\Response::__construct
     */
    public function testMessageSignatureIsVerifiedBeforeDecrypting()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settings = $this->createLegacyEncryptionSettings($settingsInfo);

        // Signed Response: decrypted
        $signedXml = file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64');
        $response = new Response($settings, $signedXml);
        $this->assertEquals(array('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/'), $response->getIssuers());

        $this->assertTrue($response->encrypted);

        // Unsigned Response: not decrypted, reported by isValid
        $unsignedXml = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $unsignedResponse = new Response($settings, $unsignedXml);
        $this->assertFalse($unsignedResponse->encrypted);
        $this->assertFalse($unsignedResponse->isValid());
        $this->assertSame(ValidationError::NO_SIGNED_MESSAGE, $unsignedResponse->getErrorException()->getCode());

        // Signed Response with a tampered ciphertext
        $dom = new DOMDocument();
        $dom->loadXML(base64_decode($signedXml));
        $xpath = new DOMXPath($dom);
        $xpath->registerNamespace('samlp', Constants::NS_SAMLP);
        $xpath->registerNamespace('saml', Constants::NS_SAML);
        $xpath->registerNamespace('xenc', Constants::NS_XENC);
        $cipherValue = $xpath->query('/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue')->item(0);
        $cipherValue->nodeValue = base64_encode(random_bytes(64));
        $tamperedXml = base64_encode($dom->saveXML());

        $tamperedResponse = new Response($settings, $tamperedXml);
        $this->assertFalse($tamperedResponse->encrypted);
        $this->assertFalse($tamperedResponse->isValid());
        $this->assertSame('Reference validation failed', $tamperedResponse->getError());

        // Without strict, the tampered ciphertext reaches the decryption
        $settingsInfo['strict'] = false;
        $settingsInfo['security']['wantMessagesSigned'] = false;
        try {
            new Response($this->createLegacyEncryptionSettings($settingsInfo), $tamperedXml);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertSame(ValidationError::DECRYPTION_FAILED, $e->getCode());
        }

        // The signature is only required in strict mode
        $settingsInfo['strict'] = false;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $response = new Response($this->createLegacyEncryptionSettings($settingsInfo), $unsignedXml);
        $this->assertTrue($response->encrypted);
        $this->assertEquals(array('http://idp.example.com/'), $response->getIssuers());
    }

    /**
     * The EncryptedID of the Subject of an EncryptedAssertion is decrypted with any
     * data and key transport algorithm, and the algorithm settings apply to it
     *
     * @covers OneLogin\Saml2\Response::decryptNameId
     */
    public function testEncryptedNameIdInEncryptedAssertionAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['security']['allowCBCEncryption'] = false;
        $withoutCBC = $this->createLegacyEncryptionSettings($settingsInfo);

        $nameId = '<saml:NameID xmlns:saml="' . Constants::NS_SAML . '">subject-nameid</saml:NameID>';
        $cases = array(
            array(XMLSecurityKey::AES128_GCM, XMLSecurityKey::RSA_OAEP_MGF1P),
            array(XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P),
            array(XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_1_5),
        );
        foreach ($cases as $case) {
            list($dataAlgorithm, $keyAlgorithm) = $case;
            $encryptedId = '<saml:EncryptedID xmlns:saml="' . Constants::NS_SAML . '">'
                . $this->encryptForSP($nameId, $keyAlgorithm, null, false, $dataAlgorithm)
                . '</saml:EncryptedID>';
            $xml = $this->buildResponseWithEncryptedAssertion($encryptedId);

            $response = new Response($this->_legacySettings, $xml);
            $this->assertTrue($response->encryptedNameId, $dataAlgorithm . ' ' . $keyAlgorithm);
            $this->assertSame('subject-nameid', $response->getNameId(), $dataAlgorithm . ' ' . $keyAlgorithm);

            if ($keyAlgorithm === XMLSecurityKey::RSA_1_5) {
                try {
                    new Response($this->createSettingsWithoutRSA15(), $xml);
                    $this->fail('Exception was not raised');
                } catch (Exception $e) {
                    $this->assertStringContainsString('Unsupported or not allowed key transport algorithm', $e->getMessage());
                }
            }
            if ($dataAlgorithm === XMLSecurityKey::AES128_CBC) {
                try {
                    new Response($withoutCBC, $xml);
                    $this->fail('Exception was not raised');
                } catch (Exception $e) {
                    $this->assertStringContainsString('Unsupported or not allowed data encryption algorithm', $e->getMessage());
                }
            }
        }
    }

    /**
     * An EncryptedAssertion whose plaintext does not declare the saml namespace (it is declared
     * by the Response) can have an EncryptedID in its Subject: the NameID can be read, with
     * the EncryptedID declaring its own namespace or not
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testEncryptedNameIdInEncryptedAssertionWithoutNamespaceDeclarations()
    {
        $nameIdDoc = new DOMDocument();
        $nameIdDoc->loadXML('<saml:NameID xmlns:saml="' . Constants::NS_SAML . '">subject-nameid</saml:NameID>');
        $encryptedNameId = $this->encryptForSP($nameIdDoc->saveXML($nameIdDoc->documentElement));

        foreach (array('<saml:EncryptedID xmlns:saml="' . Constants::NS_SAML . '">', '<saml:EncryptedID>') as $encryptedIdTag) {
            // As a child of a node that declares the namespace, the Assertion is encrypted without declaring it
            $holderXml = '<holder xmlns:saml="' . Constants::NS_SAML . '">'
                . '<saml:Assertion ID="_cccd6024116641fe48e0ae2c51220d02755f96c98d" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
                . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
                . '<saml:Subject>' . $encryptedIdTag . $encryptedNameId . '</saml:EncryptedID></saml:Subject>'
                . '</saml:Assertion></holder>';
            $holder = new DOMDocument();
            $holder->loadXML($holderXml);
            $encryptedAssertion = $this->encryptForSP($holder->documentElement->firstChild);

            $xml = '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_r1" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
                . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
                . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
                . '<saml:EncryptedAssertion>' . $encryptedAssertion . '</saml:EncryptedAssertion>'
                . '</samlp:Response>';

            $response = new Response($this->_settings, base64_encode($xml));
            $this->assertSame('subject-nameid', $response->getNameId(), $encryptedIdTag);
        }
    }

    /**
     * Only the EncryptedID of the Subject of the Assertion is decrypted
     *
     * @covers OneLogin\Saml2\Response::decryptAssertion
     */
    public function testOnlyTheEncryptedIdOfTheSubjectIsDecrypted()
    {
        $assertion = '<saml:Assertion xmlns:saml="' . Constants::NS_SAML . '" ID="_cccd6024116641fe48e0ae2c51220d02755f96c98d" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<saml:Advice>' . $this->buildEncryptedNameId() . '</saml:Advice>'
            . '<saml:Subject><saml:NameID>REAL</saml:NameID></saml:Subject>'
            . '</saml:Assertion>';

        $xml = '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_r1" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
            . '<saml:EncryptedAssertion>' . $this->encryptForSP($assertion) . '</saml:EncryptedAssertion>'
            . '</samlp:Response>';

        $response = new Response($this->_settings, base64_encode($xml));
        $this->assertFalse($response->encryptedNameId);
        $this->assertSame('REAL', $response->getNameId());
        $this->assertStringContainsString('EncryptedID', $response->getXMLDocument()->saveXML());
    }

    /**
     * EncryptedID (EncryptedKey inside its KeyInfo) inside an EncryptedAssertion
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testEncryptedNameIdInEncryptedAssertionKeyTransport()
    {
        foreach (array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_OAEP) as $keyTransport) {
            $response = new Response($this->_settings, $this->buildResponseWithEncryptedAssertion($this->buildEncryptedNameId($keyTransport)));
            $this->assertTrue($response->encryptedNameId);
            $this->assertEquals('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', $response->getNameId());
        }

        $rsa15Xml = $this->buildResponseWithEncryptedAssertion($this->buildEncryptedNameId(XMLSecurityKey::RSA_1_5));
        $response = new Response($this->_legacySettings, $rsa15Xml);
        $this->assertEquals('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', $response->getNameId());

        try {
            new Response($this->createSettingsWithoutRSA15(), $rsa15Xml);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Unsupported or not allowed key transport algorithm', $e->getMessage());
        }

        // Decrypted while constructing the Response, before any signature validation
        try {
            new Response($this->_settings, $this->buildResponseWithEncryptedAssertion($this->buildEncryptedNameId(XMLSecurityKey::RSA_OAEP_MGF1P, random_bytes(32))));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertEquals('Failure decrypting Data', $e->getMessage());
        }
    }
}
