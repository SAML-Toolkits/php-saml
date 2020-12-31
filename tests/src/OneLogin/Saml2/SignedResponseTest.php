<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;

/**
 * Unit tests for Response messages signed
 */
class SignedResponseTest extends \PHPUnit\Framework\TestCase
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
     * Tests the getNameId method of the Response
     * Case valid signed response, unsigned assertion
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testResponseSignedAssertionNot()
    {
        // The Response is signed, the Assertion is not
        $message = file_get_contents(TEST_ROOT . '/data/responses/open_saml_response.xml');
        $response = new Response($this->_settings, base64_encode($message));

        $this->assertEquals('someone@example.org', $response->getNameId());
    }

    /**
     * Tests the getNameId method of the Response
     * Case valid signed response, signed assertion
     *
     * @covers OneLogin\Saml2\Response::getNameId
     */
    public function testResponseAndAssertionSigned()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['idp']['entityId'] = "https://federate.example.net/saml/saml2/idp/metadata.php";
        $settingsInfo['sp']['entityId'] = "hello.com";
        $settings = new Settings($settingsInfo);

        // Both the Response and the Asseretion are signed
        $message = file_get_contents(TEST_ROOT . '/data/responses/simple_saml_php.xml');
        $response = new Response($settings, base64_encode($message));

        $this->assertEquals('someone@example.com', $response->getNameId());
    }
}
