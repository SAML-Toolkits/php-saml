<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;

use DomDocument;

/**
 * Unit tests for Logout Request
 */
class LogoutRequestTest extends \PHPUnit\Framework\TestCase
{
    private $_settings;

    /**
     * Initializes the Test Suite
     */
    public function setUp() : void
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $this->_settings = $settings;
    }

    /**
     * Tests the LogoutRequest Constructor.
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testConstructor()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['nameIdEncrypted'] = true;

        $settings = new Settings($settingsInfo);

        $logoutRequest = new LogoutRequest($settings);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
        $this->assertMatchesRegularExpression('#<saml:EncryptedID>#', $inflated);
    }

    /**
     * Tests the LogoutRequest Constructor.
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testConstructorWithRequest()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $encodedDeflatedRequest = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        $logoutRequest = new LogoutRequest($settings, $encodedDeflatedRequest);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#<samlp:LogoutRequest#', $inflated);
    }

    /**
     * Tests the LogoutRequest Constructor.
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testConstructorWithSessionIndex()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $sessionIndex = '_51be37965feb5579d803141076936dc2e9d1d98ebf';
        $settings = new Settings($settingsInfo);

        $logoutRequest = new LogoutRequest($settings, null, null, $sessionIndex);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);

        $sessionIndexes = LogoutRequest::getSessionIndexes($inflated);
        $this->assertIsArray($sessionIndexes);
        $this->assertEquals(array($sessionIndex), $sessionIndexes);
    }

    /**
     * Tests the LogoutRequest Constructor.
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testConstructorWithNameIdFormatOnParameter()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $nameId = 'test@example.com';
        $nameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
        $settings = new Settings($settingsInfo);

        $logoutRequest = new LogoutRequest($settings, null, $nameId, null, $nameIdFormat);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);

        $logoutNameId = LogoutRequest::getNameId($inflated);
        $this->assertEquals($nameId, $logoutNameId);

        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertEquals($nameIdFormat, $logoutNameIdData['Format']);
    }

    /**
    * Tests the LogoutRequest Constructor.
    *
    * @covers OneLogin\Saml2\LogoutRequest
    */
    public function testConstructorWithNameIdFormatOnSettings()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $nameId = 'test@example.com';
        $nameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
        $settingsInfo['sp']['NameIDFormat'] = $nameIdFormat;
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings, null, $nameId, null, null);
        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
        $logoutNameId = LogoutRequest::getNameId($inflated);
        $this->assertEquals($nameId, $logoutNameId);
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertEquals($nameIdFormat, $logoutNameIdData['Format']);
    }

    /**
    * Tests the LogoutRequest Constructor.
    *
    * @covers OneLogin\Saml2\LogoutRequest
    */
    public function testConstructorWithoutNameIdFormat()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $nameId = 'test@example.com';
        $nameIdFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $settingsInfo['sp']['NameIDFormat'] = $nameIdFormat;
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings, null, $nameId, null, null);
        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
        $logoutNameId = LogoutRequest::getNameId($inflated);
        $this->assertEquals($nameId, $logoutNameId);
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertFalse(isset($logoutNameIdData['Format']));
    }
    /**
    * Tests the LogoutRequest Constructor.
    *
    * @covers OneLogin\Saml2\LogoutRequest
    */
    public function testConstructorWithNameIdNameQualifier()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $nameId = 'test@example.com';
        $nameIdFormat = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient';
        $nameIdNameQualifier = 'https://test.example.com/saml/metadata';
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings, null, $nameId, null, $nameIdFormat, $nameIdNameQualifier);
        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
        $logoutNameId = LogoutRequest::getNameId($inflated);
        $this->assertEquals($nameId, $logoutNameId);
        $logoutNameIdData = LogoutRequest::getNameIdData($inflated);
        $this->assertEquals($nameIdFormat, $logoutNameIdData['Format']);
        $this->assertEquals($nameIdNameQualifier, $logoutNameIdData['NameQualifier']);
    }

    /**
     * Tests the LogoutRequest Constructor.
     * The creation of a deflated SAML Logout Request
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testCreateDeflatedSAMLLogoutRequestURLParameter()
    {
        $logoutRequest = new LogoutRequest($this->_settings);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
    }

    /**
     * Tests the LogoutRequest Constructor.
     * Case: Able to generate encryptedID with MultiCert
     *
     * @covers OneLogin\Saml2\LogoutRequest
     */
    public function testConstructorEncryptIdUsingX509certMulti()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';

        $settingsInfo['security']['nameIdEncrypted'] = true;

        $settings = new Settings($settingsInfo);

        $logoutRequest = new LogoutRequest($settings);

        $parameters = array('SAMLRequest' => $logoutRequest->getRequest());
        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);
        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLRequest=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLRequest'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $inflated);
        $this->assertMatchesRegularExpression('#<saml:EncryptedID>#', $inflated);
    }

    /**
     * Tests the getID method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getID
     */
    public function testGetIDFromSAMLLogoutRequest()
    {
        $logoutRequest = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');
        $id = LogoutRequest::getID($logoutRequest);
        $this->assertEquals('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', $id);

        $dom = new DOMDocument;
        $dom->loadXML($logoutRequest);
        $id2 = LogoutRequest::getID($dom);
        $this->assertEquals('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', $id2);
    }

    /**
     * Tests the getID method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getID
     */
    public function testGetIDFromDeflatedSAMLLogoutRequest()
    {
        $deflatedLogoutRequest = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');
        $decoded = base64_decode($deflatedLogoutRequest);
        $logoutRequest = gzinflate($decoded);
        $id = LogoutRequest::getID($logoutRequest);
        $this->assertEquals('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', $id);
    }

    /**
     * Tests the getNameIdData method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getNameIdData
     */
    public function testGetNameIdData()
    {
        $expectedNameIdData = array(
            'Value' => 'ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c',
            'Format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'SPNameQualifier' => 'http://idp.example.com/'
        );

        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $nameIdData = LogoutRequest::getNameIdData($request);

        $this->assertEquals($expectedNameIdData, $nameIdData);

        $dom = new DOMDocument();
        $dom->loadXML($request);
        $nameIdData2 = LogoutRequest::getNameIdData($dom);
        $this->assertEquals($expectedNameIdData, $nameIdData2);

        $request2 = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');

        try {
            $nameIdData3 = LogoutRequest::getNameIdData($request2);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Key is required in order to decrypt the NameID', $e->getMessage());
        }

        $key = $this->_settings->getSPkey();
        $nameIdData4 = LogoutRequest::getNameIdData($request2, $key);

        $expectedNameIdData = array(
            'Value' => 'ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69',
            'Format' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
            'SPNameQualifier' => 'https://pitbulk.no-ip.org/newonelogin/demo1/metadata.php'
        );

        $this->assertEquals($expectedNameIdData, $nameIdData4);

        $invRequest = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/no_nameId.xml');
        try {
            $nameIdData3 = LogoutRequest::getNameIdData($invRequest);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertStringContainsString('NameID not found in the Logout Request', $e->getMessage());
        }


        $logoutRequest = new LogoutRequest($this->_settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null, Constants::NAMEID_PERSISTENT, $this->_settings->getIdPData()['entityId'], $this->_settings->getSPData()['entityId']);
        $logoutRequestStr = $logoutRequest->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr);
        $this->assertStringContainsString('Format="'.Constants::NAMEID_PERSISTENT, $logoutRequestStr);
        $this->assertStringContainsString('NameQualifier="'.$this->_settings->getIdPData()['entityId'], $logoutRequestStr);
        $this->assertStringContainsString('SPNameQualifier="'.$this->_settings->getSPData()['entityId'], $logoutRequestStr);

        $logoutRequest2 = new LogoutRequest($this->_settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null, Constants::NAMEID_ENTITY, $this->_settings->getIdPData()['entityId'], $this->_settings->getSPData()['entityId']);
        $logoutRequestStr2 = $logoutRequest2->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr2);
        $this->assertStringContainsString('Format="'.Constants::NAMEID_ENTITY, $logoutRequestStr2);
        $this->assertStringNotContainsString('NameQualifier', $logoutRequestStr2);
        $this->assertStringNotContainsString('SPNameQualifier', $logoutRequestStr2);

        $logoutRequest3 = new LogoutRequest($this->_settings, null, "ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c", null, Constants::NAMEID_UNSPECIFIED);
        $logoutRequestStr3 = $logoutRequest3->getXML();
        $this->assertStringContainsString('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $logoutRequestStr3);
        $this->assertStringNotContainsString('Format', $logoutRequestStr3);
        $this->assertStringNotContainsString('NameQualifier', $logoutRequestStr3);
        $this->assertStringNotContainsString('SPNameQualifier', $logoutRequestStr3);
    }

    /**
     * Tests the getNameIdmethod of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getNameId
     */
    public function testGetNameId()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $nameId = LogoutRequest::getNameId($request);
        $this->assertEquals('ONELOGIN_1e442c129e1f822c8096086a1103c5ee2c7cae1c', $nameId);

        $request2 = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');
        try {
            $nameId2 = LogoutRequest::getNameId($request2);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertStringContainsString('Key is required in order to decrypt the NameID', $e->getMessage());
        }
        $key = $this->_settings->getSPkey();
        $nameId3 = LogoutRequest::getNameId($request2, $key);
        $this->assertEquals('ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69', $nameId3);
    }

    /**
     * Tests the getIssuer of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getIssuer
     */
    public function testGetIssuer()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $issuer = LogoutRequest::getIssuer($request);
        $this->assertEquals('http://idp.example.com/', $issuer);

        $dom = new DOMDocument();
        $dom->loadXML($request);
        $issuer2 = LogoutRequest::getIssuer($dom);
        $this->assertEquals('http://idp.example.com/', $issuer2);
    }

    /**
     * Tests the getSessionIndexes of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getSessionIndexes
     */
    public function testGetSessionIndexes()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $sessionIndexes = LogoutRequest::getSessionIndexes($request);
        $this->assertEmpty($sessionIndexes);

        $dom = new DOMDocument();
        $dom->loadXML($request);
        $sessionIndexes = LogoutRequest::getSessionIndexes($dom);
        $this->assertEmpty($sessionIndexes);

        $request2 = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_with_sessionindex.xml');
        $sessionIndexes2 = LogoutRequest::getSessionIndexes($request2);
        $this->assertEquals(array('_ac72a76526cb6ca19f8438e73879a0e6c8ae5131'), $sessionIndexes2);
    }

    /**
     * Tests the getError method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getError
     */
    public function testGetError()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertNull($logoutRequest->getError());

        $this->assertTrue($logoutRequest->isValid());
        $this->assertNull($logoutRequest->getError());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getError());
    }

    /**
     * Tests the getErrorException method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getErrorException
     */
    public function testGetErrorException()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertNull($logoutRequest->getError());

        $this->assertTrue($logoutRequest->isValid());
        $this->assertNull($logoutRequest->getError());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $errorException = $logoutRequest2->getErrorException();
        $this->assertStringContainsString('The LogoutRequest was received at', $errorException->getMessage());
        $this->assertEquals($errorException->getMessage(), $logoutRequest2->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     * Case Invalid Issuer
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidIssuer()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/invalid_issuer.xml');
        $currentURL = Utils::getSelfURLNoQuery();
        $request = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $request);

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertTrue($logoutRequest->isValid());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('Invalid issuer in the Logout Request', $logoutRequest2->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     * Case invalid xml
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsInValidWrongXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/invalid_xml.xml.base64');
        $response = new LogoutRequest($settings, $message);

        $this->assertTrue($response->isValid());

        $settings->setStrict(true);
        $response2 = new LogoutRequest($settings, $message);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd', $response2->getError());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new LogoutRequest($settings2, $message);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new LogoutRequest($settings2, $message);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid SAML Logout Request. Not match the saml-schema-protocol-2.0.xsd', $response4->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     * Case Invalid Destination
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidDestination()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertTrue($logoutRequest->isValid());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     * Case Invalid NotOnOrAfter
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsInvalidNotOnOrAfter()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/not_after_failed.xml');
        $currentURL = Utils::getSelfURLNoQuery();
        $request = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $request);

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertTrue($logoutRequest->isValid());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertEquals("Could not validate timestamp: expired. Check system clock.", $logoutRequest2->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsValid()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');

        $deflatedRequest = gzdeflate($request);
        $encodedRequest = base64_encode($deflatedRequest);

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertTrue($logoutRequest->isValid());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertFalse($logoutRequest2->isValid());

        $this->_settings->setStrict(false);
        $logoutRequest3 = new LogoutRequest($this->_settings, $encodedRequest);

        $currentURL = Utils::getSelfURLNoQuery();
        $request2 = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $request);

        $deflatedRequest2 = gzdeflate($request2);
        $encodedRequest2 = base64_encode($deflatedRequest2);
        $logoutRequest4 = new LogoutRequest($this->_settings, $encodedRequest2);
        $this->assertTrue($logoutRequest4->isValid());
    }

    /**
     * Tests that a 'true' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers OneLogin\Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseToCompressARequest()
    {
        //Test that we can compress.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $payload = $logoutRequest->getRequest();
        $decoded = base64_decode($payload);
        $decompressed = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $decompressed);

    }

    /**
     * Tests that a 'false' value for compress => requests gets honored when we
     * try to obtain the request payload from getRequest()
     *
     * @covers OneLogin\Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseNotToCompressARequest()
    {
        //Test that we can choose not to compress the request payload.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $payload = $logoutRequest->getRequest();
        $decoded = base64_decode($payload);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $decoded);
    }

    /**
     * Tests that we can pass a boolean value to the getRequest()
     * method to choose whether it should 'gzdeflate' the body
     * of the request.
     *
     * @covers OneLogin\Saml2\LogoutRequest::getRequest()
     */
    public function testWeCanChooseToDeflateARequestBody()
    {
        //Test that we can choose not to compress the request payload.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        //Compression is currently turned on in settings.
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $payload = $logoutRequest->getRequest(false);
        $decoded = base64_decode($payload);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $decoded);

        //Test that we can choose not to compress the request payload.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        //Compression is currently turned off in settings.
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $payload = $logoutRequest->getRequest(true);
        $decoded = base64_decode($payload);
        $decompressed = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $decompressed);
    }

    /**
     * Tests the isValid method of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsInValidSign()
    {
        $currentURL = Utils::getSelfURLNoQuery();

        $this->_settings->setStrict(false);
        $_GET = array(
            'SAMLRequest' => 'lVLBitswEP0Vo7tjWbJkSyReFkIhsN1tm6WHvQTZHmdFbUmVZLqfXzlpIS10oZdhGM17b96MtkHNk5MP9myX+AW+LxBi9jZPJsjLyw4t3kirgg7SqBmCjL083n98kGSDpfM22t5O6AbyPkKFAD5qa1B22O/QSWA+EFWPjCtaM6gBugrXHCo6Ut6UgvTV2DSkBoKyr+BDQu5QIkrwEBY4mBCViamEyyrHNCf4ueSScMnIC8r2yY02Kl5QrzG6IIvC6dgt07eNsbl2G+vPhYEf1sBkz9oUA8y2LLQZ4G3jXt1dmALKHm18Mk/+fozgk5YQNMciJ+UzKWV11Wq3q3l5mcq3/9YKenYTrL3FGkihB1fMENWgoloVt8Ut0ZX1Me3xsM+On9bk86ImPep1kv+xdKuBsg/Wzyq+f6u1ood8vLTK6JUJGkxE7WnsSDcQRirOKMc97TtWCgqU1ZyJBvM+RZbSrv/l5mrg6sbJI4T1kId1ye0JhoaQgYg+XT1dnilMSZO4uko1jPSYVF0luqQjrmR/4X8X//jC7U8=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'j/qDRTzgQw3cMDkkSkBOShqxi3t9qJxYnrADqwAECnJ3Y+iYgT33C0l/Vy3+ooQkFRyObYJqg9o7iIcMdgV6CXxpa6itVIUAI2VJewsMjzvJ4OdpePeSx7+/umVPKCfMvffsELlqo/UgxsyRZh8NMLej0ojCB7bUfIMKsiU7e0c='
        );

        $request = gzinflate(base64_decode($_GET['SAMLRequest']));
        $encodedRequest = $_GET['SAMLRequest'];

        $logoutRequest = new LogoutRequest($this->_settings, $encodedRequest);
        $this->assertTrue($logoutRequest->isValid());

        $this->_settings->setStrict(true);
        $logoutRequest2 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest2->isValid());
        $this->assertStringContainsString('The LogoutRequest was received at', $logoutRequest2->getError());

        $this->_settings->setStrict(false);
        $oldSignature = $_GET['Signature'];
        $_GET['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=';

        $logoutRequest3 = new LogoutRequest($this->_settings, $encodedRequest);

        $this->assertFalse($logoutRequest3->isValid());
        $this->assertStringContainsString('Signature validation failed. Logout Request rejected', $logoutRequest3->getError());

        $_GET['Signature'] = $oldSignature;
        $oldSigAlg = $_GET['SigAlg'];
        unset($_GET['SigAlg']);

        $this->assertTrue($logoutRequest3->isValid());

        $oldRelayState = $_GET['RelayState'];
        $_GET['RelayState'] = 'http://example.com/relaystate';

        $this->assertFalse($logoutRequest3->isValid());
        $this->assertStringContainsString('Signature validation failed. Logout Request rejected', $logoutRequest3->getError());

        $this->_settings->setStrict(true);

        $request2 = str_replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', $currentURL, $request);
        $request2 = str_replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/', $request2);

        $deflatedRequest2 = gzdeflate($request2);
        $encodedRequest2 = base64_encode($deflatedRequest2);

        $_GET['SAMLRequest'] = $encodedRequest2;
        $logoutRequest4 = new LogoutRequest($this->_settings, $encodedRequest2);

        $this->assertFalse($logoutRequest4->isValid());
        $this->assertEquals('Signature validation failed. Logout Request rejected', $logoutRequest4->getError());

        $this->_settings->setStrict(false);
        $logoutRequest5 = new LogoutRequest($this->_settings, $encodedRequest2);

        $this->assertFalse($logoutRequest5->isValid());
        $this->assertEquals('Signature validation failed. Logout Request rejected', $logoutRequest5->getError());


        $_GET['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';

        $this->assertFalse($logoutRequest5->isValid());
        $this->assertEquals('Invalid signAlg in the received Logout Request', $logoutRequest5->getError());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;

        $settings = new Settings($settingsInfo);

        $_GET['SigAlg'] = $oldSigAlg;
        $oldSignature = $_GET['Signature'];
        unset($_GET['Signature']);
        $logoutRequest6 = new LogoutRequest($settings, $encodedRequest2);

        $this->assertFalse($logoutRequest6->isValid());
        $this->assertEquals('The Message of the Logout Request is not signed and the SP require it', $logoutRequest6->getError());

        $_GET['Signature'] = $oldSignature;

        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        unset($settingsInfo['idp']['x509cert']);
        $settings2 = new Settings($settingsInfo);
        $logoutRequest7 = new LogoutRequest($settings2, $encodedRequest2);

        $this->assertFalse($logoutRequest7->isValid());
        $this->assertStringContainsString('In order to validate the sign on the Logout Request, the x509cert of the IdP is required', $logoutRequest7->getError());
    }

    /**
     * Tests the isValid method of the LogoutRequest
     * Case: Using x509certMulti
     *
     * @covers OneLogin\Saml2\LogoutRequest::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        $_GET = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $encodedRequest = $_GET['SAMLRequest'];
        $settings = new Settings($settingsInfo);
        $settings->setBaseURL("http://stuff.com/endpoints/endpoints/");
        $_SERVER['REQUEST_URI'] = "/endpoints/endpoints/sls.php";
        $logoutRequest = new LogoutRequest($settings, $encodedRequest);
        $valid = $logoutRequest->isValid();
        unset($_SERVER['REQUEST_URI']);
        Utils::setBaseURL(null);
        $this->assertTrue($valid);
    }

    /**
     * Tests that we can get the request XML directly without
     * going through intermediate steps
     *
     * @covers OneLogin\Saml2\LogoutRequest::getXML()
     */
    public function testGetXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $xml = $logoutRequest->getXML();
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $xml);

        $logoutRequestProcessed = new LogoutRequest($settings, base64_encode($xml));
        $xml2 = $logoutRequestProcessed->getXML();
        $this->assertMatchesRegularExpression('#^<samlp:LogoutRequest#', $xml2);
    }

    /**
     * Tests that we can get the ID of the LogoutRequest
     *
     * @covers OneLogin\Saml2\LogoutRequest::getID()
     */
    public function testGetID()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $xml = $logoutRequest->getXML();
        $id1 = LogoutRequest::getID($xml);
        $this->assertNotNull($id1);

        $logoutRequestProcessed = new LogoutRequest($settings, base64_encode($xml));
        $id2 = $logoutRequestProcessed->id;
        $this->assertEquals($id1, $id2);
    }

    /**
     * Tests that the LogoutRequest throws an exception
     *
     * @covers OneLogin\Saml2\LogoutRequest::getID()
     */
    public function testGetIDException()
    {
        $this->expectException(Error::class);
        $this->expectExceptionMessage('LogoutRequest could not be processed');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settings = new Settings($settingsInfo);
        $logoutRequest = new LogoutRequest($settings);
        $xml = $logoutRequest->getXML();
        $id1 = LogoutRequest::getID($xml.'<garbage>');
    }
}
