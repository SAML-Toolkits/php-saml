<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\LogoutResponse;

use DomDocument;

/**
 * Unit tests for Logout Response
 */
class LogoutResponseTest extends \PHPUnit\Framework\TestCase
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
     * Tests the LogoutResponse Constructor.
     *
     * @covers OneLogin\Saml2\LogoutResponse
     */
    public function testConstructor()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $response = new LogoutResponse($this->_settings, $message);
        $this->assertMatchesRegularExpression('#<samlp:LogoutResponse#', $response->document->saveXML());
    }

    /**
     * Tests the LogoutResponse Constructor.
     * The creation of a deflated SAML Logout Response
     *
     * @covers OneLogin\Saml2\LogoutResponse
     */
    public function testCreateDeflatedSAMLLogoutResponseURLParameter()
    {
        $inResponseTo = 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e';
        $responseBuilder = new LogoutResponse($this->_settings);
        $responseBuilder->build($inResponseTo);
        $parameters = array('SAMLResponse' => $responseBuilder->getResponse());

        $logoutUrl = Utils::redirect('http://idp.example.com/SingleLogoutService.php', $parameters, true);

        $this->assertMatchesRegularExpression('#^http://idp\.example\.com\/SingleLogoutService\.php\?SAMLResponse=#', $logoutUrl);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $exploded);
        // parse_url already urldecode de params so is not required.
        $payload = $exploded['SAMLResponse'];
        $decoded = base64_decode($payload);
        $inflated = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $inflated);
    }

    /**
     * Tests the getStatus method of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::getStatus
     */
    public function testGetStatus()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $response = new LogoutResponse($this->_settings, $message);
        $status = $response->getStatus();
        $this->assertEquals($status, Constants::STATUS_SUCCESS);

        $message2 = file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/no_status.xml.base64');
        $response2 = new LogoutResponse($this->_settings, $message2);
        $this->assertNULL($response2->getStatus());
    }

    /**
     * Tests the getIssuer of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::getIssuer
     */
    public function testGetIssuer()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $response = new LogoutResponse($this->_settings, $message);

        $issuer = $response->getIssuer($response);
        $this->assertEquals('http://idp.example.com/', $issuer);
    }

    /**
     * Tests the private method _query of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::_query
     */
    public function testQuery()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $response = new LogoutResponse($this->_settings, $message);

        $issuer = $response->getIssuer($response);
        $this->assertEquals('http://idp.example.com/', $issuer);
    }

    /**
     * Tests the getError method of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::getError
     */
    public function testGetError()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $requestId = 'invalid_request_id';
        $response = new LogoutResponse($this->_settings, $message);
        $this->_settings->setStrict(true);
        $this->assertFalse($response->isValid($requestId));
        $this->assertEquals($response->getError(), 'The InResponseTo of the Logout Response: ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e, does not match the ID of the Logout request sent by the SP: invalid_request_id');
    }


    /**
     * Tests the getError method of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::getErrorException
     */
    public function testGetErrorException()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $requestId = 'invalid_request_id';
        $response = new LogoutResponse($this->_settings, $message);
        $this->_settings->setStrict(true);
        $this->assertFalse($response->isValid($requestId));
        $errorException = $response->getErrorException();
        $this->assertEquals('The InResponseTo of the Logout Response: ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e, does not match the ID of the Logout request sent by the SP: invalid_request_id', $errorException->getMessage());
        $this->assertEquals($errorException->getMessage(), $response->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     * Case invalid request Id
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidRequestId()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $requestId = 'invalid_request_id';

        $this->_settings->setStrict(false);
        $response = new LogoutResponse($this->_settings, $message);
        $this->assertTrue($response->isValid($requestId));

        $this->_settings->setStrict(true);
        $response2 = new LogoutResponse($this->_settings, $message);

        $this->assertTrue($response2->isValid());

        $this->assertFalse($response2->isValid($requestId));
        $this->assertStringContainsString('The InResponseTo of the Logout Response:', $response2->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     * Case invalid Issuer
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidIssuer()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $plainMessage = str_replace('http://idp.example.com/', 'http://invalid.issuer.example.com', $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $this->_settings->setStrict(false);
        $response = new LogoutResponse($this->_settings, $message);
        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new LogoutResponse($this->_settings, $message);

        $this->assertFalse($response2->isValid());
        $this->assertEquals('Invalid issuer in the Logout Response', $response2->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     * Case invalid xml
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidWrongXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['wantXMLValidation'] = false;

        $settings = new Settings($settingsInfo);
        $settings->setStrict(false);

        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/invalid_xml.xml.base64');

        $response = new LogoutResponse($settings, $message);

        $this->assertTrue($response->isValid());

        $settings->setStrict(true);
        $response2 = new LogoutResponse($settings, $message);
        $response2->isValid();
        $this->assertNotEquals('Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd', $response2->getError());

        $settingsInfo['security']['wantXMLValidation'] = true;
        $settings2 = new Settings($settingsInfo);
        $settings2->setStrict(false);
        $response3 = new LogoutResponse($settings2, $message);
        $this->assertTrue($response3->isValid());

        $settings2->setStrict(true);
        $response4 = new LogoutResponse($settings2, $message);
        $this->assertFalse($response4->isValid());
        $this->assertEquals('Invalid SAML Logout Response. Not match the saml-schema-protocol-2.0.xsd', $response4->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     * Case invalid Destination
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testIsInValidDestination()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        $this->_settings->setStrict(false);
        $response = new LogoutResponse($this->_settings, $message);
        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new LogoutResponse($this->_settings, $message);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('The LogoutResponse was received at', $response2->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     */
    public function testIsInValidSign()
    {
        $currentURL = Utils::getSelfURLNoQuery();

        $this->_settings->setStrict(false);
        $_GET = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );

        $response = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('Invalid issuer in the Logout Response', $response2->getError());

        $this->_settings->setStrict(false);
        $oldSignature = $_GET['Signature'];
        $_GET['Signature'] = 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVf3333=';
        $response3 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);

        $this->assertFalse($response3->isValid());
        $this->assertEquals('Signature validation failed. Logout Response rejected', $response3->getError());

        $_GET['Signature'] = $oldSignature;
        $oldSigAlg = $_GET['SigAlg'];
        unset($_GET['SigAlg']);
        $response4 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertTrue($response4->isValid());

        $oldRelayState = $_GET['RelayState'];
        $_GET['RelayState'] = 'http://example.com/relaystate';
        $response5 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertFalse($response5->isValid());
        $this->assertEquals('Signature validation failed. Logout Response rejected', $response5->getError());

        $this->_settings->setStrict(true);

        $plainMessage6 = gzinflate(base64_decode($_GET['SAMLResponse']));
        $plainMessage6 = str_replace('https://pitbulk.no-ip.org/newonelogin/demo1/index.php?sls', $currentURL, $plainMessage6);
        $plainMessage6 = str_replace('https://pitbulk.no-ip.org/simplesaml/saml2/idp/metadata.php', 'http://idp.example.com/', $plainMessage6);
        $_GET['SAMLResponse'] = base64_encode(gzdeflate($plainMessage6));

        $response6 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertFalse($response6->isValid());
        $this->assertEquals('Signature validation failed. Logout Response rejected', $response6->getError());

        $this->_settings->setStrict(false);
        $response7 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertFalse($response7->isValid());
        $this->assertEquals('Signature validation failed. Logout Response rejected', $response7->getError());

        $_GET['SigAlg'] = 'http://www.w3.org/2000/09/xmldsig#dsa-sha1';
        $response8 = new LogoutResponse($this->_settings, $_GET['SAMLResponse']);
        $this->assertFalse($response8->isValid());
        $this->assertEquals('Invalid signAlg in the received Logout Response', $response8->getError());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;

        $settings = new Settings($settingsInfo);

        $_GET['SigAlg'] = $oldSigAlg;
        $oldSignature = $_GET['Signature'];
        unset($_GET['Signature']);
        $_GET['SAMLResponse'] = base64_encode(gzdeflate($plainMessage6));
        $response9 = new LogoutResponse($settings, $_GET['SAMLResponse']);
        $this->assertFalse($response9->isValid());
        $this->assertEquals('The Message of the Logout Response is not signed and the SP requires it', $response9->getError());

        $_GET['Signature'] = $oldSignature;

        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        unset($settingsInfo['idp']['x509cert']);
        $settings2 = new Settings($settingsInfo);

        $response10 = new LogoutResponse($settings2, $_GET['SAMLResponse']);
        $this->assertFalse($response10->isValid());
        $this->assertEquals('In order to validate the sign on the Logout Response, the x509cert of the IdP is required', $response10->getError());
    }

    /**
     * Tests the isValid method of the LogoutResponse
     * Case: Using x509certMulti
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     */
    public function testIsValidSignUsingX509certMulti()
    {
        $_GET = array(
            'SAMLResponse' => 'fZHbasJAEIZfJey9ZrNZc1gSodRSBKtQxYveyGQz1kCyu2Q24OM3jS21UHo3p++f4Z+CoGud2th3O/hXJGcNYXDtWkNqapVs6I2yQA0pAx2S8lrtH142Ssy5cr31VtuW3SH/E0CEvW+sYcF6VbLTIktFLMWZgxQR8DSP85wDB4GJGMOqShYVaoBUsOCIPY1kyUahEScacG3Ig/FjiUdyxuOZ4IcoUVGq4vSNBSsk3xjwE3Xx3qkwJD+cz3NtuxBN7WxjPN1F1NLcXdwob77tONiS7bZPm93zenvCqopxgVJmuU50jREsZF4noKWAOuNZJbNznnBky+LTDDVd2S+/dje1m+MVOtfidEER3g8Vt2fsPfiBfmePtsbgCO2A/9tL07TaD1ojEQuXtw0/ouFfD19+AA==',
            'RelayState' => 'http://stuff.com/endpoints/endpoints/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'OV9c4R0COSjN69fAKCpV7Uj/yx6/KFxvbluVCzdK3UuortpNMpgHFF2wYNlMSG9GcYGk6p3I8nB7Z+1TQchMWZOlO/StjAqgtZhtpiwPcWryNuq8vm/6hnJ3zMDhHTS7F8KG4qkCXmJ9sQD3Y31UNcuygBwIbNakvhDT5Qo9Nsw='
        );

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $encodedResponse = $_GET['SAMLResponse'];
        $settings = new Settings($settingsInfo);
        $settings->setBaseURL("http://stuff.com/endpoints/endpoints/");
        $_SERVER['REQUEST_URI'] = "/endpoints/endpoints/sls.php";
        $logoutResponse = new LogoutResponse($settings, $_GET['SAMLResponse']);
        $valid = $logoutResponse->isValid();
        unset($_SERVER['REQUEST_URI']);
        Utils::setBaseURL(null);
        $this->assertTrue($valid);
    }

    /**
     * Tests the isValid method of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutResponse::isValid
     */
    public function testIsValid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $response = new LogoutResponse($this->_settings, $message);

        $this->assertTrue($response->isValid());

        $this->_settings->setStrict(true);
        $response2 = new LogoutResponse($this->_settings, $message);
        $this->assertFalse($response2->isValid());
        $this->assertStringContainsString('The LogoutResponse was received at', $response2->getError());

        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message3 = base64_encode(gzdeflate($plainMessage));

        $response3 = new LogoutResponse($this->_settings, $message3);
        $this->assertTrue($response3->isValid());
    }

    /**
     * Tests that a 'true' value for compress => responses gets honored when we
     * try to obtain the request payload from getResponse()
     *
     * @covers OneLogin\Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseToCompressAResponse()
    {
        //Test that we can compress.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $message = file_get_contents(
            TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
        );

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings, $message);
        $payload = $logoutResponse->getResponse();
        $decoded = base64_decode($payload);
        $decompressed = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $decompressed);

    }

    /**
     * Tests that a 'false' value for compress => responses gets honored when we
     * try to obtain the request payload from getResponse()
     *
     * @covers OneLogin\Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseNotToCompressAResponse()
    {
        //Test that we can choose not to compress the request payload.
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $message = file_get_contents(
            TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
        );

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings, $message);
        $payload = $logoutResponse->getResponse();
        $decoded = base64_decode($payload);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $decoded);
    }

    /**
     * Test that we can choose to compress or not compress the request payload
     * with getResponse() method.
     *
     * @covers OneLogin\Saml2\LogoutResponse::getResponse()
     */
    public function testWeCanChooseToDeflateAResponseBody()
    {

        $message = file_get_contents(
            TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64'
        );

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings, $message);
        $payload = $logoutResponse->getResponse(false);
        $decoded = base64_decode($payload);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $decoded);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings, $message);
        $payload = $logoutResponse->getResponse(true);
        $decoded = base64_decode($payload);
        $decompressed = gzinflate($decoded);
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $decompressed);
    }

    /**
     * Tests that we can get the request XML directly without
     * going through intermediate steps
     *
     * @covers OneLogin\Saml2\LogoutResponse::getXML()
     */
    public function testGetXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings);
        $logoutResponse->build('jhgvsadja');
        $xml = $logoutResponse->getXML();
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $xml);

        $processedLogoutResponse = new LogoutResponse($settings, base64_encode($xml));
        $xml2 = $processedLogoutResponse->getXML();
        $this->assertMatchesRegularExpression('#^<samlp:LogoutResponse#', $xml2);
    }

    /**
     * Tests that we can get the ID of the LogoutResponse
     *
     * @covers OneLogin\Saml2\LogoutRequest::getID()
     */
    public function testGetID()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings);
        $logoutResponse->build('jhgvsadja');

        $xml = $logoutResponse->getXML();
        $id1 = $logoutResponse->getID();
        $this->assertNotNull($id1);

        $processedLogoutResponse = new LogoutResponse($settings, base64_encode($xml));
        $id2 = $processedLogoutResponse->getID();
        $this->assertEquals($id1, $id2);
    }

    /**
     * Tests that the LogoutRequest throws an exception
     *
     * @covers OneLogin\Saml2\LogoutResponse::getID()
     */
    public function testGetIDException()
    {
        $this->expectException(Error::class);
        $this->expectExceptionMessage('LogoutResponse could not be processed');

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settings = new Settings($settingsInfo);
        $logoutResponse = new LogoutResponse($settings, '<garbage>');
    }
}
