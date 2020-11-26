<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;

use RobRichards\XMLSecLibs\XMLSecurityKey;

use Exception;

/**
 * Unit tests for Auth class
 */
class AuthTest extends \PHPUnit\Framework\TestCase
{
    private $_auth;
    private $_settingsInfo;

    /**
     * Initializes the Test Suite
     */
    public function setUp()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $this->_settingsInfo = $settingsInfo;
        $this->_auth = new Auth($settingsInfo);
    }

    /**
     * Tests the getSettings method of the OneLogin\Saml2\Auth class
     * Build a Settings object with a setting array
     * and compare the value returned from the method of the
     * $auth object
     *
     * @covers OneLogin\Saml2\Auth::getSettings
     */
    public function testGetSettings()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $authSettings = $this->_auth->getSettings();
        $this->assertEquals($authSettings, $settings);
    }

    /**
     * Tests the getLastRequestID method of the Auth class
     *
     * @covers OneLogin\Saml2\Auth::getLastRequestID
     */
    public function testGetLastRequestID()
    {
        $targetSSOURL = $this->_auth->login(null, array(), false, false, true, false);
        $id1 = $this->_auth->getLastRequestID();
        $this->assertNotNull($id1);

        $targetSLOURL = $this->_auth->logout(null, array(), null, null, true, null);
        $id2 = $this->_auth->getLastRequestID();
        $this->assertNotNull($id2);

        $this->assertNotEquals($id1, $id2);
    }

    /**
     * Tests the getSSOurl method of the Auth class
     *
     * @covers OneLogin\Saml2\Auth::getSSOurl
     */
    public function testGetSSOurl()
    {
        $ssoUrl = $this->_settingsInfo['idp']['singleSignOnService']['url'];
        $this->assertEquals($this->_auth->getSSOurl(), $ssoUrl);
    }

    /**
     * Tests the getSLOurl method of the Auth class
     *
     * @covers OneLogin\Saml2\Auth::getSLOurl
     */
    public function testGetSLOurl()
    {
        $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
        $this->assertEquals($this->_auth->getSLOurl(), $sloUrl);
    }

    /**
     * Tests the getSLOResponseUrl method of the Auth class
     *
     * @covers OneLogin\Saml2\Auth::getSLOResponseUrl
     */
    public function testGetSLOResponseUrl()
    {
        $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
        $this->assertEquals($this->_auth->getSLOResponseUrl(), $sloUrl);
    }


    /**
     * Tests the processResponse method of the Auth class
     * Case No Response, An exception is throw
     *
     * @covers OneLogin\Saml2\Auth::processResponse
     */
    public function testProcessNoResponse()
    {
        try {
            $this->_auth->processResponse();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('SAML Response not found', $e->getMessage());
        }

        $this->assertEquals($this->_auth->getErrors(), array('invalid_binding'));
    }

    /**
     * Tests the processResponse method of the Auth class
     * Case Invalid Response, After processing the response the user
     * is not authenticated, attributes are notreturned, no nameID and
     * the error array is not empty, contains 'invalid_response
     *
     * @covers OneLogin\Saml2\Auth::processResponse
     * @covers OneLogin\Saml2\Auth::isAuthenticated
     * @covers OneLogin\Saml2\Auth::getAttributes
     * @covers OneLogin\Saml2\Auth::getAttribute
     * @covers OneLogin\Saml2\Auth::getNameId
     * @covers OneLogin\Saml2\Auth::getNameIdFormat
     * @covers OneLogin\Saml2\Auth::getNameIdNameQualifier
     * @covers OneLogin\Saml2\Auth::getNameIdSPNameQualifier
     * @covers OneLogin\Saml2\Auth::getErrors
     * @covers OneLogin\Saml2\Auth::getSessionIndex
     * @covers OneLogin\Saml2\Auth::getSessionExpiration
     * @covers OneLogin\Saml2\Auth::getLastErrorReason
     * @covers OneLogin\Saml2\Auth::getLastErrorException
     */
    public function testProcessResponseInvalid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64');
        $_POST['SAMLResponse'] = $message;

        $this->_auth->processResponse();

        $this->assertFalse($this->_auth->isAuthenticated());
        $this->assertEmpty($this->_auth->getAttributes());
        $this->assertNull($this->_auth->getNameId());
        $this->assertNull($this->_auth->getNameIdFormat());
        $this->assertNull($this->_auth->getNameIdNameQualifier());
        $this->assertNull($this->_auth->getNameIdSPNameQualifier());
        $this->assertNull($this->_auth->getSessionIndex());
        $this->assertNull($this->_auth->getSessionExpiration());
        $this->assertNull($this->_auth->getAttribute('uid'));
        $this->assertEquals($this->_auth->getErrors(), array('invalid_response'));
        $this->assertEquals($this->_auth->getLastErrorReason(), "Reference validation failed");
        $errorException = $this->_auth->getLastErrorException();
        $this->assertEquals("Reference validation failed", $errorException->getMessage());
    }

    /**
     * Tests the processResponse method of the Auth class
     * Case Invalid Response, Invalid requestID
     *
     * @covers OneLogin\Saml2\Auth::processResponse
     */
    public function testProcessResponseInvalidRequestId()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/unsigned_response.xml.base64');

        $plainMessage = base64_decode($message);
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/acs.php', $currentURL, $plainMessage);

        $_POST['SAMLResponse'] = base64_encode($plainMessage);

        $requestId = 'invalid';
        $this->_auth->processResponse($requestId);

        $this->assertEquals("No Signature found. SAML Response rejected", $this->_auth->getLastErrorReason());
        $errorException = $this->_auth->getLastErrorException();
        $this->assertEquals("No Signature found. SAML Response rejected", $errorException->getMessage());

        $this->_auth->setStrict(true);
        $this->_auth->processResponse($requestId);
        $this->assertEquals("The InResponseTo of the Response: _57bcbf70-7b1f-012e-c821-782bcb13bb38, does not match the ID of the AuthNRequest sent by the SP: invalid", $this->_auth->getLastErrorReason());

        $validRequestId = '_57bcbf70-7b1f-012e-c821-782bcb13bb38';
        $this->_auth->processResponse($validRequestId);
        $this->assertEquals("No Signature found. SAML Response rejected", $this->_auth->getLastErrorReason());
    }

    /**
     * Tests the processResponse method of the Auth class
     * Case Valid Response, After processing the response the user
     * is authenticated, attributes are returned, also has a nameID and
     * the error array is empty
     *
     * @covers OneLogin\Saml2\Auth::processResponse
     * @covers OneLogin\Saml2\Auth::isAuthenticated
     * @covers OneLogin\Saml2\Auth::getAttributes
     * @covers OneLogin\Saml2\Auth::getAttribute
     * @covers OneLogin\Saml2\Auth::getNameId
     * @covers OneLogin\Saml2\Auth::getNameIdFormat
     * @covers OneLogin\Saml2\Auth::getSessionIndex
     * @covers OneLogin\Saml2\Auth::getSessionExpiration
     * @covers OneLogin\Saml2\Auth::getErrors
     */
    public function testProcessResponseValid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $_POST['SAMLResponse'] = $message;

        $this->_auth->processResponse();
        $this->assertTrue($this->_auth->isAuthenticated());
        $this->assertEquals('492882615acf31c8096b627245d76ae53036c090', $this->_auth->getNameId());
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', $this->_auth->getNameIdFormat());
        $attributes = $this->_auth->getAttributes();
        $this->assertNotEmpty($attributes);
        $this->assertEquals($this->_auth->getAttribute('mail'), $attributes['mail']);
        $sessionIndex = $this->_auth->getSessionIndex();
        $this->assertNotNull($sessionIndex);
        $this->assertEquals('_6273d77b8cde0c333ec79d22a9fa0003b9fe2d75cb', $sessionIndex);
        $sessionExpiration = $this->_auth->getSessionExpiration();
        $this->assertNotNull($sessionExpiration);
        $this->assertEquals('2655106621', $sessionExpiration);
    }

    /**
     * Tests the getNameIdNameQualifier method of the Auth class
     * Case found
     * @covers OneLogin\Saml2\Auth::getNameIdNameQualifier
     */
    public function testGetNameIdNameQualifier()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response_with_namequalifier.xml.base64');
        $_POST['SAMLResponse'] = $message;
        $this->assertNull($this->_auth->getNameIdNameQualifier());
        $this->_auth->processResponse();
        $this->assertTrue($this->_auth->isAuthenticated());
        $this->assertEquals('https://test.example.com/saml/metadata', $this->_auth->getNameIdNameQualifier());
    }

    /**
     * Tests the getNameIdNameQualifier method of the Auth class
     * Case Null
     * @covers OneLogin\Saml2\Auth::getNameIdNameQualifier
     */
    public function testGetNameIdNameQualifier2()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $_POST['SAMLResponse'] = $message;
        $this->assertNull($this->_auth->getNameIdNameQualifier());
        $this->_auth->processResponse();
        $this->assertTrue($this->_auth->isAuthenticated());
        $this->assertNull($this->_auth->getNameIdNameQualifier());
    }

    /**
     * Tests the getNameIdSPNameQualifier method of the Auth class
     * Case Found
     * @covers OneLogin\Saml2\Auth::getNameIdSPNameQualifier
     */
    public function testGetNameIdSPNameQualifier()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response_with_namequalifier.xml.base64');
        $_POST['SAMLResponse'] = $message;
        $this->assertNull($this->_auth->getNameIdSPNameQualifier());
        $this->_auth->processResponse();
        $this->assertTrue($this->_auth->isAuthenticated());
        $this->assertNull($this->_auth->getNameIdSPNameQualifier());
    }

    /**
     * Tests the getNameIdSPNameQualifier method of the Auth class
     * Case Null
     * @covers OneLogin\Saml2\Auth::getNameIdSPNameQualifier
     */
    public function testGetNameIdSPNameQualifier2()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $_POST['SAMLResponse'] = $message;
        $this->assertNull($this->_auth->getNameIdSPNameQualifier());
        $this->_auth->processResponse();
        $this->assertTrue($this->_auth->isAuthenticated());
        $this->assertEquals('http://stuff.com/endpoints/metadata.php', $this->_auth->getNameIdSPNameQualifier());
    }

    /**
     * Tests the getAttributes and getAttributesWithFriendlyName methods
     * @covers OneLogin\Saml2\Auth::getAttributes
     * @covers OneLogin\Saml2\Auth::getAttribute
     * @covers OneLogin\Saml2\Auth::getAttributesWithFriendlyName
     * @covers OneLogin\Saml2\Auth::getAttributeWithFriendlyName
     */
    public function testGetAttributes()
    {
        $auth = new Auth($this->_settingsInfo);
        $response = file_get_contents(TEST_ROOT . '/data/responses/response6.xml.base64');
        $_POST['SAMLResponse'] = $response;
        $auth->processResponse();
        $expectedAttributes = array(
            'urn:oid:0.9.2342.19200300.100.1.1' => array(
                'demo'
            ),
            'urn:oid:2.5.4.42' => array(
                'value'
            ),
        );
        $expectedFriendlyNameAttributes = array(
            'uid' => array(
                'demo'
            ),
            'givenName' => array(
                'value'
            ),
        );
        $this->assertEquals($expectedAttributes, $auth->getAttributes());
        $this->assertEquals($expectedFriendlyNameAttributes, $auth->getAttributesWithFriendlyName());
        $this->assertNull($auth->getAttribute('givenName'));
        $this->assertEquals(array('value'), $auth->getAttributeWithFriendlyName('givenName'));
        $this->assertEquals(array('value'), $auth->getAttribute('urn:oid:2.5.4.42'));
        $this->assertNull($auth->getAttributeWithFriendlyName('urn:oid:2.5.4.42'));
        // An assertion that has no attributes should return an empty array when asked for the attributes
        $response2 = file_get_contents(TEST_ROOT . '/data/responses/response2.xml.base64');
        $_POST['SAMLResponse'] = $response2;
        $auth2 = new Auth($this->_settingsInfo);
        $auth2->processResponse();
        $this->assertEmpty($auth2->getAttributes());
        $this->assertEmpty($auth2->getAttributesWithFriendlyName());
        // Encrypted Attributes are not supported
        $response3 = file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_attrs.xml.base64');
        $_POST['SAMLResponse'] = $response3;
        $auth3 = new Auth($this->_settingsInfo);
        $auth3->processResponse();
        $this->assertEmpty($auth3->getAttributes());
        $this->assertEmpty($auth3->getAttributesWithFriendlyName());
        // Duplicated Attribute names
        $response4 = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes_with_friendly_names.xml.base64');
        $_POST['SAMLResponse'] = $response4;
        $auth4 = new Auth($this->_settingsInfo);
        try {
            $auth4->processResponse();
            $this->fail('OneLogin\Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Found an Attribute element with duplicated FriendlyName', $e->getMessage());
        }
        $response5 = file_get_contents(TEST_ROOT . '/data/responses/invalids/duplicated_attributes.xml.base64');
        $_POST['SAMLResponse'] = $response5;
        $auth5 = new Auth($this->_settingsInfo);
        try {
            $auth5->processResponse();
            $this->fail('OneLogin\Saml2\ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Found an Attribute element with duplicated Name', $e->getMessage());
        }
    }

    /**
     * Tests the redirectTo method of the Auth class
     * (phpunit raises an exception when a redirect is executed, the
     * exception is catched and we check that the targetURL is correct)
     * Case redirect without url parameter
     *
     * @covers OneLogin\Saml2\Auth::redirectTo
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testRedirectTo()
    {
        try {
            $relayState = 'http://sp.example.com';
            $_REQUEST['RelayState'] = $relayState;
            // The Header of the redirect produces an Exception
            $this->_auth->redirectTo();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);

            $this->assertEquals($targetUrl, $relayState);
        }
    }

    /**
     * Tests the redirectTo method of the Auth class
     * (phpunit raises an exception when a redirect is executed, the
     * exception is catched and we check that the targetURL is correct)
     * Case redirect with url parameter
     *
     * @covers OneLogin\Saml2\Auth::redirectTo
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testRedirectTowithUrl()
    {
        try {
            $relayState = 'http://sp.example.com';
            $url2 = 'http://sp2.example.com';
            $_REQUEST['RelayState'] = $relayState;
            // The Header of the redirect produces an Exception
            $this->_auth->redirectTo($url2);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);

            $this->assertEquals($targetUrl, $url2);
        }
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case No Message, An exception is throw
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessNoSLO()
    {
        try {
            $this->_auth->processSLO(true);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('SAML LogoutRequest/LogoutResponse not found', $e->getMessage());
        }

        $this->assertEquals($this->_auth->getErrors(), array('invalid_binding'));
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Invalid Logout Response
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseInvalid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $_GET['SAMLResponse'] = $message;

        $this->_auth->processSLO(true);
        $this->assertEmpty($this->_auth->getErrors());

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true);
        // The Destination fails
        $this->assertEquals($this->_auth->getErrors(), array('invalid_logout_response'));

        $this->_auth->setStrict(false);
        $this->_auth->processSLO(true);
        $this->assertEmpty($this->_auth->getErrors());
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Logout Response not sucess
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseNoSucess()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/invalids/status_code_responder.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLResponse'] = $message;

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true);
        $this->assertEquals($this->_auth->getErrors(), array('logout_not_success'));
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Logout Response with valid and invalid Request ID
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseRequestId()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLResponse'] = $message;
        $requestID = 'wrongID';

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true, $requestID);
        $this->assertEquals($this->_auth->getErrors(), array('invalid_logout_response'));

        $requestID = 'ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e';
        $this->_auth->processSLO(true, $requestID);
        $this->assertEmpty($this->_auth->getErrors());
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Response
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLResponse'] = $message;

        if (!isset($_SESSION)) {
            $_SESSION = array();
        }
        $_SESSION['samltest'] = true;

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true);

        $this->assertEmpty($this->_auth->getErrors());

        // Session keep alive
        $this->assertTrue(isset($_SESSION['samltest']));
        $this->assertTrue($_SESSION['samltest']);
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Response, validating deleting the local session
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValidDeletingSession()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        if (!isset($_SESSION)) {
            $_SESSION = array();
        }
        $_SESSION['samltest'] = true;

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLResponse'] = $message;

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(false);

        $this->assertEmpty($this->_auth->getErrors());

        $this->assertFalse(isset($_SESSION['samltest']));
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Response, validating deleting the local session
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     */
    public function testProcessSLOResponseValidDeletingSessionCallback()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');

        if (!isset($_SESSION)) {
            $_SESSION = array();
        }
        $_SESSION['samltest'] = true;

        $callback = function () {
            $_SESSION['samltest'] = false;
        };

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLResponse'] = $message;

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(false, null, false, $callback);

        $this->assertEmpty($this->_auth->getErrors());

        $this->assertTrue(isset($_SESSION['samltest']));
        $this->assertFalse($_SESSION['samltest']);
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Invalid Logout Request
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestInvalidValid()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');
        $_GET['SAMLRequest'] = $message;

        $targetUrl = $this->_auth->processSLO(true, null, false, null, true);
        $parsedQuery = getParamsFromUrl($targetUrl);

        $this->assertEmpty($this->_auth->getErrors());
        $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
        $this->assertContains($sloResponseUrl, $targetUrl);
        $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
        $this->assertArrayNotHasKey('RelayState', $parsedQuery);

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true);
        // Fail due destination missmatch
        $this->assertEquals($this->_auth->getErrors(), array('invalid_logout_request'));

        $this->_auth->setStrict(false);
        $targetUrl = $this->_auth->processSLO(true, null, false, null, true);
        $parsedQuery = getParamsFromUrl($targetUrl);

        $this->assertEmpty($this->_auth->getErrors());
        $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
        $this->assertContains($sloResponseUrl, $targetUrl);
        $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
        $this->assertArrayNotHasKey('RelayState', $parsedQuery);
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Logout Request NotOnOrAfter failed
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestNotOnOrAfterFailed()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/invalids/not_after_failed.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLRequest'] = $message;

        $this->_auth->setStrict(true);
        $this->_auth->processSLO(true);
        $this->assertEquals($this->_auth->getErrors(), array('invalid_logout_request'));
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Request, validating that the local session is deleted,
     * a LogoutResponse is created and a redirection executed
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestDeletingSession()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLRequest'] = $message;

        if (!isset($_SESSION)) {
            $_SESSION = array();
        }
        $_SESSION['samltest'] = true;

        try {
            $this->_auth->setStrict(true);
            $this->_auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
            $this->assertContains($sloResponseUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            // Session is not alive
            $this->assertFalse(isset($_SESSION['samltest']));
        }

        $_SESSION['samltest'] = true;

        try {
            $this->_auth->setStrict(true);
            $this->_auth->processSLO(true);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
            $this->assertContains($sloResponseUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            // Session is alive
            $this->assertTrue(isset($_SESSION['samltest']));
            $this->assertTrue($_SESSION['samltest']);
        }
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Request, validating that the local session is
     * deleted with callback, a LogoutResponse is created and
     * a redirection executed
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestDeletingSessionCallback()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLRequest'] = $message;

        if (!isset($_SESSION)) {
            $_SESSION = array();
        }
        $_SESSION['samltest'] = true;

        $callback = function () {
            $_SESSION['samltest'] = false;
        };

        try {
            $this->_auth->setStrict(true);
            $this->_auth->processSLO(false, null, false, $callback);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];;;
            $this->assertContains($sloResponseUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayNotHasKey('RelayState', $parsedQuery);

            if (getenv("TRAVIS")) {
                // Can't test that on TRAVIS
                $this->markTestSkipped("Can't test that on TRAVIS");
            } else {
                // Session is alive
                $this->assertTrue(isset($_SESSION['samltest']));
                // But has been modified
                $this->assertFalse($_SESSION['samltest']);
            }
        }
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Request, validating the relayState,
     * a LogoutResponse is created and a redirection executed
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestRelayState()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLRequest'] = $message;
        $_GET['RelayState'] = 'http://relaystate.com';

        try {
            $this->_auth->setStrict(true);
            $this->_auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
            $this->assertContains($sloResponseUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals('http://relaystate.com', $parsedQuery['RelayState']);
        }
    }

    /**
     * Tests the processSLO method of the Auth class
     * Case Valid Logout Request, validating the relayState,
     * a signed LogoutResponse is created and a redirection executed
     *
     * @covers OneLogin\Saml2\Auth::processSLO
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProcessSLORequestSignedResponse()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['logoutResponseSigned'] = true;

        $auth = new Auth($settingsInfo);

        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');

        // In order to avoid the destination problem
        $plainMessage = gzinflate(base64_decode($message));
        $currentURL = Utils::getSelfURLNoQuery();
        $plainMessage = str_replace('http://stuff.com/endpoints/endpoints/sls.php', $currentURL, $plainMessage);
        $message = base64_encode(gzdeflate($plainMessage));

        $_GET['SAMLRequest'] = $message;
        $_GET['RelayState'] = 'http://relaystate.com';

        try {
            $auth->setStrict(true);
            $auth->processSLO(false);
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloResponseUrl = $this->_settingsInfo['idp']['singleLogoutService']['responseUrl'];
            $this->assertContains($sloResponseUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLResponse', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertEquals('http://relaystate.com', $parsedQuery['RelayState']);
            $this->assertEquals(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login with no parameters. An AuthnRequest is built an redirection executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogin()
    {
        try {
            // The Header of the redirect produces an Exception
            $this->_auth->login();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $this->_settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], Utils::getSelfRoutedURLNoQuery());
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login with relayState. An AuthnRequest is built. GET with SAMLRequest,
     * and RelayState. A redirection is executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginWithRelayState()
    {
        try {
            $relayState = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $this->_auth->login($relayState);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $this->_settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $relayState);
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login with $elaySate and $parameters. An AuthnRequest is built. GET with
     * SAMLRequest, RelayState and extra parameters in the GET. A redirection is executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginWithRelayStateAndParameters()
    {
        try {
            $relayState = 'http://sp.example.com';
            $parameters = array('test1' => 'value1', 'test2' => 'value2');

            // The Header of the redirect produces an Exception
            $this->_auth->login($relayState, $parameters);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $this->_settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $relayState);
            $this->assertArrayHasKey('test1', $parsedQuery);
            $this->assertArrayHasKey('test2', $parsedQuery);
            $this->assertEquals($parsedQuery['test1'], $parameters['test1']);
            $this->assertEquals($parsedQuery['test2'], $parameters['test2']);
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login signed. An AuthnRequest signed is built an redirect executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginSigned()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $returnTo);
            $this->assertEquals(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login with no parameters. A AuthN Request is built with ForceAuthn and redirect executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginForceAuthN()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $encodedRequest = $parsedQuery['SAMLRequest'];
            $decoded = base64_decode($encodedRequest);
            $request = gzinflate($decoded);
            $this->assertNotContains('ForceAuthn="true"', $request);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';

            $auth->login($returnTo, array(), false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace2 = $e->getTrace();
            $targetUrl2 = getUrlFromRedirect($trace2);
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $ssoUrl2 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl2, $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $encodedRequest2 = $parsedQuery2['SAMLRequest'];
            $decoded2 = base64_decode($encodedRequest2);
            $request2 = gzinflate($decoded2);
            $this->assertNotContains('ForceAuthn="true"', $request2);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), true, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace3 = $e->getTrace();
            $targetUrl3 = getUrlFromRedirect($trace3);
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $ssoUrl3 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl3, $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $encodedRequest3 = $parsedQuery3['SAMLRequest'];
            $decoded3 = base64_decode($encodedRequest3);
            $request3 = gzinflate($decoded3);
            $this->assertContains('ForceAuthn="true"', $request3);
        }

    }

    /**
     * Tests the login method of the Auth class
     * Case Login with no parameters. A AuthN Request is built with IsPassive and redirect executed
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginIsPassive()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['authnRequestsSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $encodedRequest = $parsedQuery['SAMLRequest'];
            $decoded = base64_decode($encodedRequest);
            $request = gzinflate($decoded);
            $this->assertNotContains('IsPassive="true"', $request);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace2 = $e->getTrace();
            $targetUrl2 = getUrlFromRedirect($trace2);
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $ssoUrl2 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl2, $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $encodedRequest2 = $parsedQuery2['SAMLRequest'];
            $decoded2 = base64_decode($encodedRequest2);
            $request2 = gzinflate($decoded2);
            $this->assertNotContains('IsPassive="true"', $request2);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), false, true);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace3 = $e->getTrace();
            $targetUrl3 = getUrlFromRedirect($trace3);
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $ssoUrl3 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl3, $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $encodedRequest3 = $parsedQuery3['SAMLRequest'];
            $decoded3 = base64_decode($encodedRequest3);
            $request3 = gzinflate($decoded3);
            $this->assertContains('IsPassive="true"', $request3);
        }
    }

    /**
     * Tests the login method of the Auth class
     * Case Login with no parameters. A AuthN Request is built with and without NameIDPolicy
     *
     * @covers OneLogin\Saml2\Auth::login
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLoginNameIDPolicy()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), false, false, false, false);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $encodedRequest = $parsedQuery['SAMLRequest'];
            $decoded = base64_decode($encodedRequest);
            $request = gzinflate($decoded);
            $this->assertNotContains('<samlp:NameIDPolicy', $request);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), false, false, false, true);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace2 = $e->getTrace();
            $targetUrl2 = getUrlFromRedirect($trace2);
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $ssoUrl2 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl2, $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $encodedRequest2 = $parsedQuery2['SAMLRequest'];
            $decoded2 = base64_decode($encodedRequest2);
            $request2 = gzinflate($decoded2);
            $this->assertContains('<samlp:NameIDPolicy', $request2);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace3 = $e->getTrace();
            $targetUrl3 = getUrlFromRedirect($trace3);
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $ssoUrl3 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl3, $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $encodedRequest3 = $parsedQuery3['SAMLRequest'];
            $decoded3 = base64_decode($encodedRequest3);
            $request3 = gzinflate($decoded3);
            $this->assertContains('<samlp:NameIDPolicy', $request3);
        }
    }

    /**
    * Tests the login method of the Auth class
    * Case Login with no parameters. A AuthN Request is built with and without Subject
    *
    * @covers OneLogin\Saml2\Auth::login
    * @runInSeparateProcess
    */
    public function testLoginSubject()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $encodedRequest = $parsedQuery['SAMLRequest'];
            $decoded = base64_decode($encodedRequest);
            $request = gzinflate($decoded);
            $this->assertNotContains('<saml:Subject', $request);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->login($returnTo, array(), false, false, false, true, "testuser@example.com");
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace2 = $e->getTrace();
            $targetUrl2 = getUrlFromRedirect($trace2);
            $parsedQuery2 = getParamsFromUrl($targetUrl2);

            $ssoUrl2 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl2, $targetUrl2);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery2);
            $encodedRequest2 = $parsedQuery2['SAMLRequest'];
            $decoded2 = base64_decode($encodedRequest2);
            $request2 = gzinflate($decoded2);
            $this->assertContains('<saml:Subject', $request2);
            $this->assertContains('Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">testuser@example.com</saml:NameID>', $request2);
            $this->assertContains('<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">', $request2);
        }

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $settingsInfo['sp']['NameIDFormat'] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            $auth2 = new Auth($settingsInfo);
            $auth2->login($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace3 = $e->getTrace();
            $targetUrl3 = getUrlFromRedirect($trace3);
            $parsedQuery3 = getParamsFromUrl($targetUrl3);

            $ssoUrl3 = $settingsInfo['idp']['singleSignOnService']['url'];
            $this->assertContains($ssoUrl3, $targetUrl3);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery3);
            $encodedRequest3 = $parsedQuery3['SAMLRequest'];
            $decoded3 = base64_decode($encodedRequest3);
            $request3 = gzinflate($decoded3);
            $this->assertContains('<saml:Subject', $request3);
            $this->assertContains('Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">testuser@example.com</saml:NameID>', $request3);
            $this->assertContains('<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">', $request3);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case Logout with no parameters. A logout Request is built and redirect executed
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogout()
    {
        try {
            // The Header of the redirect produces an Exception
            $this->_auth->logout();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], Utils::getSelfRoutedURLNoQuery());
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case Logout with relayState. A logout Request is build. GET with SAMLRequest,
     * RelayState. A redirection is executed
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithRelayState()
    {
        try {
            $relayState = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $this->_auth->logout($relayState);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $relayState);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case Logout with relayState + parameters. A logout Request is build. GET with SAMLRequest,
     * RelayState and extra parameters. A redirection is executed
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithRelayStateAndParameters()
    {
        try {
            $relayState = 'http://sp.example.com';
            $parameters = array('test1' => 'value1', 'test2' => 'value2');

            // The Header of the redirect produces an Exception
            $this->_auth->logout($relayState, $parameters);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $relayState);
            $this->assertArrayHasKey('test1', $parsedQuery);
            $this->assertArrayHasKey('test2', $parsedQuery);
            $this->assertEquals($parsedQuery['test1'], $parameters['test1']);
            $this->assertEquals($parsedQuery['test2'], $parameters['test2']);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case Logout with relayState + NameID + SessionIndex. A logout Request is build. GET with SAMLRequest.
     * A redirection is executed
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutWithNameIdAndSessionIndex()
    {
        try {
            $relayState = 'http://sp.example.com';
            // The Header of the redirect produces an Exception
            $nameId = 'my_name_id';
            $sessionIndex = '_51be37965feb5579d803141076936dc2e9d1d98ebf';
            $this->_auth->logout(null, array(), $nameId, $sessionIndex);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case nameID loaded after process SAML Response
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutNameID()
    {
        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $_POST['SAMLResponse'] = $message;
        $this->_auth->processResponse();
        $nameIdFromResponse = $this->_auth->getNameId();

        try {
            $nameId = 'my_name_id';
            $this->_auth->logout();
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $this->_settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);

            $logoutRequest = gzinflate(base64_decode($parsedQuery['SAMLRequest']));
            $nameIdFromRequest = LogoutRequest::getNameId($logoutRequest);
            $this->assertEquals($nameIdFromResponse, $nameIdFromRequest);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case Logout signed. A logout Request signed in
     * the assertion is built and redirect executed
     *
     * @covers OneLogin\Saml2\Auth::logout
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testLogoutSigned()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['logoutRequestSigned'] = true;

        $auth = new Auth($settingsInfo);

        try {
            // The Header of the redirect produces an Exception
            $returnTo = 'http://example.com/returnto';
            $auth->logout($returnTo);
            // Do not ever get here
            $this->assertFalse(true);
        } catch (Exception $e) {
            $this->assertContains('Cannot modify header information', $e->getMessage());
            $trace = $e->getTrace();
            $targetUrl = getUrlFromRedirect($trace);
            $parsedQuery = getParamsFromUrl($targetUrl);

            $sloUrl = $settingsInfo['idp']['singleLogoutService']['url'];
            $this->assertContains($sloUrl, $targetUrl);
            $this->assertArrayHasKey('SAMLRequest', $parsedQuery);
            $this->assertArrayHasKey('RelayState', $parsedQuery);
            $this->assertArrayHasKey('SigAlg', $parsedQuery);
            $this->assertArrayHasKey('Signature', $parsedQuery);
            $this->assertEquals($parsedQuery['RelayState'], $returnTo);
            $this->assertEquals(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);
        }
    }

    /**
     * Tests the logout method of the Auth class
     * Case IdP no SLO endpoint.
     *
     * @covers OneLogin\Saml2\Auth::logout
     */
    public function testLogoutNoSLO()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        unset($settingsInfo['idp']['singleLogoutService']);

        $auth = new Auth($settingsInfo);

        try {
            $returnTo = 'http://example.com/returnto';
            $auth->logout($returnTo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('The IdP does not support Single Log Out', $e->getMessage());
        }
    }

    /**
     * Tests the setStrict method of the Auth
     *
     * @covers OneLogin\Saml2\Auth::setStrict
     */
    public function testSetStrict()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        $settingsInfo['strict'] = false;

        $auth = new Auth($settingsInfo);

        $settings = $auth->getSettings();
        $this->assertFalse($settings->isStrict());

        $auth->setStrict(true);
        $settings = $auth->getSettings();
        $this->assertTrue($settings->isStrict());

        $auth->setStrict(false);
        $settings = $auth->getSettings();
        $this->assertFalse($settings->isStrict());

        try {
            $auth->setStrict('a');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid value passed to setStrict()', $e->getMessage());
        }
    }

    /**
     * Tests the buildRequestSignature method of the Auth
     *
     * @covers OneLogin\Saml2\Auth::buildRequestSignature
     */
    public function testBuildRequestSignature()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');
        $relayState = 'http://relaystate.com';
        $signature = $this->_auth->buildRequestSignature($message, $relayState);
        $validSignature = 'CqdIlbO6GieeJFV+PYqyqz1QVJunQXdZZl+ZyIby9O3/eMJM0XHi+TWReRrpgNxKkbmmvx5fp/t7mphbLiVYNMgGINEaaa/OfoaGwU9GM5YCVULA2t7qZBel1yrIXGMxijJizB7UPR2ZMo4G+Wdhx1zbmbB0GYM0A27w6YCe/+k=';
        $this->assertEquals($validSignature, $signature);
    }

    /**
     * Tests the buildResponseSignature method of the Auth
     *
     * @covers OneLogin\Saml2\Auth::buildResponseSignature
     */
    public function testBuildResponseSignature()
    {
        $message = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response_deflated.xml.base64');
        $relayState = 'http://relaystate.com';
        $signature = $this->_auth->buildResponseSignature($message, $relayState);
        $validSignature = 'fFGaOuO/2+ch/xlwU5o7iS6R+v2quWchLAtiDyQTxStFQZKY1NsBs/eYIin2Meq7oTl1Ks6tpT6JshH5OwhPh/08K7M2oa6FIKb99cjg+jIJ/WwpuJ5h9SH0XXP8y3RLhCxLIomHDsBOGQK8WvOlXFUg+9nvOaEMNi6raUWrGhA=';
        $this->assertEquals($validSignature, $signature);
    }

    /**
     * Tests that we can get most recently constructed
     * SAML AuthNRequest
     *
     * @covers OneLogin\Saml2\Auth::getLastRequestXML()
     */
    public function testGetLastAuthNRequest()
    {
        $targetSSOURL = $this->_auth->login(null, array(), false, false, true, false);
        $parsedQuery = getParamsFromUrl($targetSSOURL);
        $decodedSamlRequest = gzinflate(base64_decode($parsedQuery['SAMLRequest']));
        $this->assertEquals($decodedSamlRequest, $this->_auth->getLastRequestXML());
    }

    /**
     * Tests that we can get most recently constructed
     * LogoutResponse.
     *
     * @covers OneLogin\Saml2\Auth::getLastRequestXML()
     */
    public function testGetLastLogoutRequestSent()
    {
        $targetSLOURL = $this->_auth->logout(null, array(), null, null, true, null);
        $parsedQuery = getParamsFromUrl($targetSLOURL);
        $decodedLogoutRequest = gzinflate(base64_decode($parsedQuery['SAMLRequest']));
        $this->assertEquals($decodedLogoutRequest, $this->_auth->getLastRequestXML());
    }

    /**
     * Tests that we can get most recently processed
     * LogoutRequest.
     *
     * @covers OneLogin\Saml2\Auth::getLastRequestXML()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetLastLogoutRequestReceived()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');
        $_GET['SAMLRequest'] = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml.base64');
        $this->_auth->processSLO(false, null, false, null, true);
        $this->assertEquals($xml, $this->_auth->getLastRequestXML());
    }

    /**
     * Tests that we can get most recently processed
     * SAML Response
     *
     * @covers OneLogin\Saml2\Auth::getLastResponseXML()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetLastSAMLResponse()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml');
        $this->_auth->processResponse();
        file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml');
        $this->assertEquals($response, $this->_auth->getLastResponseXML());

        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64');
        $decryptedResponse = file_get_contents(TEST_ROOT . '/data/responses/decrypted_valid_encrypted_assertion.xml');
        $this->_auth->processResponse();
        $this->assertEquals($decryptedResponse, $this->_auth->getLastResponseXML());
    }

    /**
     * Tests that we can get most recently constructed
     * LogoutResponse.
     *
     * @covers OneLogin\Saml2\Auth::getLastResponseXML()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetLastLogoutResponseSent()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $_GET['SAMLRequest'] = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml.base64');

        $auth = new Auth($settingsInfo);
        $targetSLOURL = $auth->processSLO(false, null, false, null, true);
        $parsedQuery = getParamsFromUrl($targetSLOURL);
        $decodedLogoutResponse = gzinflate(base64_decode($parsedQuery['SAMLResponse']));
        $this->assertEquals($decodedLogoutResponse, $auth->getLastResponseXML());

        $settingsInfo['compress'] = array(
            'responses' => true
        );
        $auth2 = new Auth($settingsInfo);
        $targetSLOURL2 = $auth2->processSLO(false, null, false, null, true);
        $parsedQuery2 = getParamsFromUrl($targetSLOURL2);
        $decodedLogoutResponse2 = gzinflate(base64_decode($parsedQuery2['SAMLResponse']));
        $this->assertEquals($decodedLogoutResponse2, $auth2->getLastResponseXML());

        $settingsInfo['compress'] = array(
            'responses' => false
        );
        $auth3 = new Auth($settingsInfo);
        $targetSLOURL3 = $auth3->processSLO(false, null, false, null, true);
        $parsedQuery3 = getParamsFromUrl($targetSLOURL3);
        $decodedLogoutResponse3 = base64_decode($parsedQuery3['SAMLResponse']);
        $this->assertEquals($decodedLogoutResponse3, $auth3->getLastResponseXML());
    }

    /**
     * Tests that we can get most recently processed
     * LogoutResponse.
     *
     * @covers OneLogin\Saml2\Auth::getLastResponseXML()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetLastLogoutResponseReceived()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml');
        $_GET['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64');
        $this->_auth->processSLO(false, null, false, null, true);
        $this->assertEquals($xml, $this->_auth->getLastResponseXML());
    }

    /**
     * Tests that we can get the Id of the SAMLResponse and
     * the assertion processed and the NotOnOrAfter value
     *
     * @covers OneLogin\Saml2\Auth::getLastMessageId()
     * @covers OneLogin\Saml2\Auth::getLastAssertionId()
     * @covers OneLogin\Saml2\Auth::getLastAssertionNotOnOrAfter()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetInfoFromLastResponseReceived()
    {
        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64');
        $response = file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml');
        $this->_auth->processResponse();
        $this->assertEmpty($this->_auth->getErrors());
        $this->assertEquals('pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375', $this->_auth->getLastMessageId());
        $this->assertEquals('_cccd6024116641fe48e0ae2c51220d02755f96c98d', $this->_auth->getLastAssertionId());
        $this->assertNull($this->_auth->getLastAssertionNotOnOrAfter());

        $_POST['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64');
        $this->_auth->processResponse();
        $this->assertEmpty($this->_auth->getErrors());
        $this->assertEquals('pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e', $this->_auth->getLastMessageId());
        $this->assertEquals('pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb', $this->_auth->getLastAssertionId());
        $this->assertNull($this->_auth->getLastAssertionNotOnOrAfter());

        // NotOnOrAfter is calculated with strict = true
        // If invalid, response id and assertion id are not obtained

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['strict'] = true;
        $auth = new Auth($settingsInfo);

        $auth->processResponse();
        $this->assertNotEmpty($auth->getErrors());
        $this->assertNull($auth->getLastMessageId());
        $this->assertNull($auth->getLastMessageId());
        $this->assertNull($auth->getLastAssertionId());
        $this->assertNull($auth->getLastAssertionNotOnOrAfter());

        Utils::setSelfProtocol('https');
        Utils::setSelfHost('pitbulk.no-ip.org');
        $auth->processResponse();
        $this->assertEmpty($auth->getErrors());
        $this->assertEquals('pfx42be40bf-39c3-77f0-c6ae-8bf2e23a1a2e', $auth->getLastMessageId());
        $this->assertEquals('pfx57dfda60-b211-4cda-0f63-6d5deb69e5bb', $auth->getLastAssertionId());
        $this->assertEquals(2671081021, $auth->getLastAssertionNotOnOrAfter());
    }

    /**
     * Tests that we can get the Id of the LogoutRequest processed
     *
     * @covers OneLogin\Saml2\Auth::getLastMessageId()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetIdFromLastLogoutRequest()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml');
        $_GET['SAMLRequest'] = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml.base64');
        $this->_auth->processSLO(false, null, false, null, true);
        $this->assertEquals('ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e', $this->_auth->getLastMessageId());
    }

    /**
     * Tests that we can get the Id of the LogoutResponse processed
     *
     * @covers OneLogin\Saml2\Auth::getLastMessageId()
     */
    public function testGetIdFromLastLogoutResponse()
    {
        $xml = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml');
        $_GET['SAMLResponse'] = file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64');
        $this->_auth->processSLO(false, null, false, null, true);
        $this->assertEquals('_f9ee61bd9dbf63606faa9ae3b10548d5b3656fb859', $this->_auth->getLastMessageId());
    }
}
