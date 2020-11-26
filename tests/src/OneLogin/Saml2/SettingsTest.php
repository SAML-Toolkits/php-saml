<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Error;
use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

use Exception;

/**
 * Unit tests for Setting class
 */
class SettingsTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Tests the Settings Constructor.
     * Case load setting from array
     *
     * @covers OneLogin\Saml2\Settings
     */
    public function testLoadSettingsFromArray()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $this->assertEmpty($settings->getErrors());

        unset($settingsInfo['sp']['NameIDFormat']);
        unset($settingsInfo['idp']['x509cert']);
        $settingsInfo['idp']['certFingerprint'] = 'afe71c28ef740bc87425be13a2263d37971daA1f9';
        $this->assertEmpty($settings->getErrors());

        unset($settingsInfo['sp']);
        unset($settingsInfo['idp']);

        try {
            $settings2 = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('Invalid array settings', $e->getMessage());
        }

        include $settingsDir.'settings2.php';

        $settings3 = new Settings($settingsInfo);
        $this->assertEmpty($settings3->getErrors());
    }

    /**
     * Tests the Settings Constructor.
     * Case load setting from file
     *
     * @covers OneLogin\Saml2\Settings
     */
    public function testLoadSettingsFromFile()
    {
        $settings = new Settings();

        $this->assertEmpty($settings->getErrors());
    }

    /**
     * Tests getCertPath method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getBasePath
     * @covers OneLogin\Saml2\Settings::getCertPath
     */
    public function testGetCertPath()
    {
        $settings = new Settings();

        $this->assertEquals(ONELOGIN_CUSTOMPATH.'certs/', $settings->getCertPath());
    }

    /**
     * Tests getLibPath method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getLibPath
     */
    public function testGetLibPath()
    {
        $settings = new Settings();
        $base = $settings->getBasePath();

        $this->assertEquals($base.'src/Saml2/', $settings->getLibPath());
    }

    /**
     * Tests getSchemasPath method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getSchemasPath
     */
    public function testGetSchemasPath()
    {
        $settings = new Settings();
        $base = $settings->getBasePath();

        $this->assertEquals($base.'src/Saml2/schemas/', $settings->getSchemasPath());

    }

    /**
     * Tests getSchemasPath method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::setSchemasPath
     */
    public function testSetSchemasPath()
    {
        $settings = new Settings();
        $base = $settings->getBasePath();

        $this->assertEquals($base.'src/Saml2/schemas/', $settings->getSchemasPath());

        $settings->setSchemasPath('custompath/');
        $this->assertEquals('custompath/', $settings->getSchemasPath());
    }

    /**
     * Tests shouldCompressRequests method of Settings.
     *
     * @covers OneLogin\Saml2\Settings::shouldCompressRequests
     */
    public function testShouldCompressRequests()
    {
        //The default value should be true.
        $settings = new Settings();
        $this->assertTrue($settings->shouldCompressRequests());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        //settings1.php contains a true value for compress => requests.
        $settings = new Settings($settingsInfo);
        $this->assertTrue($settings->shouldCompressRequests());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        //settings2 contains a false value for compress => requests.
        $settings = new Settings($settingsInfo);
        $this->assertFalse($settings->shouldCompressRequests());
    }

    /**
     * Tests shouldCompressResponses method of Settings.
     *
     * @covers OneLogin\Saml2\Settings::shouldCompressResponses
     */
    public function testShouldCompressResponses()
    {
        //The default value should be true.
        $settings = new Settings();
        $this->assertTrue($settings->shouldCompressResponses());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        //settings1.php contains a true value for compress => responses.
        $settings = new Settings($settingsInfo);
        $this->assertTrue($settings->shouldCompressResponses());

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        //settings2 contains a false value for compress => responses.
        $settings = new Settings($settingsInfo);
        $this->assertFalse($settings->shouldCompressResponses());
    }

    /**
     * Tests the checkCompressionSettings method of Settings.
     *
     * @dataProvider invalidCompressSettingsProvider
     * @param string $invalidValue invalidCompressSettingsProvider
     *
     * @covers OneLogin\Saml2\Settings::checkCompressionSettings
     */
    public function testNonArrayCompressionSettingsCauseSyntaxError($invalidValue)
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['compress'] = $invalidValue;

        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $expectedMessage = "Invalid array settings: invalid_syntax";
            $this->assertEquals($expectedMessage, $e->getMessage());
            return;
        }

        $this->fail("An Error should have been caught.");
    }

    /**
     * Tests the checkCompressionSettings method of Settings.
     *
     * @dataProvider invalidCompressSettingsProvider
     * @param string $invalidValue invalidCompressSettingsProvider
     *
     * @covers OneLogin\Saml2\Settings::checkCompressionSettings
     */
    public function testThatOnlyBooleansCanBeUsedForCompressionSettings($invalidValue)
    {
        $requestsIsInvalid = false;
        $responsesIsInvalid = false;

        try {
            $settingsDir = TEST_ROOT .'/settings/';
            include $settingsDir.'settings1.php';

            $settingsInfo['compress']['requests'] = $invalidValue;
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
             $expectedMessage = "Invalid array settings: 'compress'=>'requests' values must be true or false.";
             $this->assertEquals($expectedMessage, $e->getMessage());
             $requestsIsInvalid = true;
        }

        try {
            $settingsDir = TEST_ROOT .'/settings/';
            include $settingsDir.'settings1.php';

            $settingsInfo['compress']['responses'] = $invalidValue;
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
             $expectedMessage = "Invalid array settings: 'compress'=>'responses' values must be true or false.";
             $this->assertEquals($expectedMessage, $e->getMessage());
             $responsesIsInvalid = true;
        }

        $this->assertTrue($requestsIsInvalid);
        $this->assertTrue($responsesIsInvalid);
    }

    public function invalidCompressSettingsProvider()
    {
        return array(
            array(1),
            array(0.1),
            array(new \stdClass),
            array("A random string.")
        );
    }

    /**
     * Tests the checkSPCerts method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::checkSPCerts
     * @covers OneLogin\Saml2\Settings::getSPcert
     * @covers OneLogin\Saml2\Settings::getSPcertNew
     * @covers OneLogin\Saml2\Settings::getSPkey
     */
    public function testCheckSPCerts()
    {
        $settings = new Settings();

        $this->assertTrue($settings->checkSPCerts());


        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings2 = new Settings($settingsInfo);
        $this->assertTrue($settings2->checkSPCerts());

        $this->assertEquals($settings2->getSPkey(), $settings->getSPkey());
        $this->assertEquals($settings2->getSPcert(), $settings->getSPcert());
        $this->assertNull($settings2->getSPcertNew());

        include $settingsDir.'settings5.php';
        $settings3 = new Settings($settingsInfo);
        $this->assertTrue($settings3->checkSPCerts());

        $this->assertEquals($settings3->getSPkey(), $settings->getSPkey());
        $this->assertEquals($settings3->getSPcert(), $settings->getSPcert());
        $this->assertNotNull($settings3->getSPcertNew());
        $this->assertNotEquals($settings3->getSPcertNew(), $settings3->getSPcert());
    }

    /**
     * Tests the checkSettings method of the Settings
     * The checkSettings method is private and is used at the constructor
     *
     * @covers OneLogin\Saml2\Settings::checkSettings
     */
    public function testCheckSettings()
    {
        $settingsInfo = array();

        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('Invalid array settings: invalid_syntax', $e->getMessage());
        }

        $settingsInfo['strict'] = true;
        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('idp_not_found', $e->getMessage());
            $this->assertContains('sp_not_found', $e->getMessage());
        }

        $settingsInfo['idp'] = array();
        $settingsInfo['idp']['x509cert'] = '';
        $settingsInfo['sp'] = array();
        $settingsInfo['sp']['entityID'] = 'SPentityId';
        $settingsInfo['security'] = array();
        $settingsInfo['security']['signMetadata'] = false;
        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('idp_entityId_not_found', $e->getMessage());
            $this->assertContains('idp_sso_not_found', $e->getMessage());
            $this->assertContains('sp_entityId_not_found', $e->getMessage());
            $this->assertContains('sp_acs_not_found', $e->getMessage());
        }

        $settingsInfo['idp']['entityID'] = 'entityId';
        $settingsInfo['idp']['singleSignOnService']['url'] = 'invalid_value';
        $settingsInfo['idp']['singleLogoutService']['url'] = 'invalid_value';
        $settingsInfo['idp']['singleLogoutService']['responseUrl'] = 'invalid_value';
        $settingsInfo['sp']['assertionConsumerService']['url'] = 'invalid_value';
        $settingsInfo['sp']['singleLogoutService']['url'] = 'invalid_value';
        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('idp_sso_url_invalid', $e->getMessage());
            $this->assertContains('idp_slo_url_invalid', $e->getMessage());
            $this->assertContains('idp_slo_response_url_invalid', $e->getMessage());
            $this->assertContains('sp_acs_url_invalid', $e->getMessage());
            $this->assertContains('sp_sls_url_invalid', $e->getMessage());
        }

        $settingsInfo['security']['wantAssertionsSigned'] = true;
        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('idp_cert_or_fingerprint_not_found_and_required', $e->getMessage());
        }

        $settingsInfo['security']['nameIdEncrypted'] = true;
        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('idp_cert_not_found_and_required', $e->getMessage());
        }

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['security']['signMetadata']['keyFileName'] = 'metadata.key';
        $settingsInfo['organization'] = array(
            'en-US' => array(
                'name' => 'miss_information'
            )
        );

        $settingsInfo['contactPerson'] = array(
            'support' => array(
                'givenName' => 'support_name'
            ),
            'auxiliar' => array(
                'givenName' => 'auxiliar_name',
                'emailAddress' => 'auxiliar@example.com',
            ),
        );

        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('sp_signMetadata_invalid', $e->getMessage());
            $this->assertContains('organization_not_enought_data', $e->getMessage());
            $this->assertContains('contact_type_invalid', $e->getMessage());
        }

        $settingsInfo['security']['signMetadata'] = ['privateKey' => file_get_contents(TEST_ROOT . '/data/customPath/certs/metadata.key')];

        try {
            $settings = new Settings($settingsInfo);
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('sp_signMetadata_invalid', $e->getMessage());
            $this->assertContains('organization_not_enought_data', $e->getMessage());
            $this->assertContains('contact_type_invalid', $e->getMessage());
        }
    }

    /**
    * Tests the getIdPSSOurl method of the Settings class
    *
    * @covers OneLogin\Saml2\Settings::getIdPSSOurl
    */
    public function testGetIdPSSOurl()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $ssoUrl = "http://idp.example.com/SSOService.php";
        $this->assertEquals($settings->getIdPSSOUrl(), $ssoUrl);
    }

    /**
    * Tests the getIdPSLOurl method of the Settings class
    *
    * @covers OneLogin\Saml2\Settings::getIdPSLOurl
    */
    public function testGetIdPSLOurl()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $sloUrl = "http://idp.example.com/SingleLogoutService.php";
        $this->assertEquals($settings->getIdPSLOUrl(), $sloUrl);

        include $settingsDir.'settings2.php';
        $settings2 = new Settings($settingsInfo);

        $sloUrl = "http://idp.example.com/SingleLogoutService.php";
        $this->assertEquals($settings2->getIdPSLOUrl(), $sloUrl);
    }

    /**
     * Tests the getIdPSLOResponseUrl method of the Settings class
     *
     * @covers OneLogin\Saml2\Settings::getIdPSLOResponseUrl
     */
    public function testGetIdPSLOResponseUrl()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $sloUrl = "http://idp.example.com/SingleLogoutServiceResponse.php";
        $this->assertEquals($settings->getIdPSLOResponseUrl(), $sloUrl);

        include $settingsDir.'settings2.php';
        $settings2 = new Settings($settingsInfo);

        $sloUrl = "http://idp.example.com/SingleLogoutService.php";
        $this->assertEquals($settings2->getIdPSLOUrl(), $sloUrl);
    }

    /**
     * Tests the getSPMetadata method of the Settings
     * Case unsigned metadata
     *
     * @covers OneLogin\Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadata()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = $settings->getSPMetadata();

        $this->assertNotEmpty($metadata);

        $this->assertContains('<md:SPSSODescriptor', $metadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata);
        $this->assertContains('WantAssertionsSigned="false"', $metadata);
        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata);
        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);
    }

    /**
     * Tests the getSPMetadata method of the Settings
     * Case with x509certNew
     *
     * @covers OneLogin\Saml2\Settings::getSPMetadata
     * @dataProvider getSPMetadataWithX509CertNewDataProvider
     */
    public function testGetSPMetadataWithX509CertNew($alwaysIncludeEncryption, $wantNameIdEncrypted, $wantAssertionsEncrypted, $expectEncryptionKeyDescriptor)
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings5.php';
        $settingsInfo['security']['wantNameIdEncrypted'] = $wantNameIdEncrypted;
        $settingsInfo['security']['wantAssertionsEncrypted'] = $wantAssertionsEncrypted;
        $settings = new Settings($settingsInfo);
        $metadata = $settings->getSPMetadata($alwaysIncludeEncryption);
        $this->assertEquals($expectEncryptionKeyDescriptor ? 4 : 2, substr_count($metadata, "<md:KeyDescriptor"));
        // signing KeyDescriptor should always be included
        $this->assertEquals(2, substr_count($metadata, '<md:KeyDescriptor use="signing"'));
        $this->assertEquals($expectEncryptionKeyDescriptor ? 2 : 0, substr_count($metadata, '<md:KeyDescriptor use="encryption"'));
    }

    public function getSPMetadataWithX509CertNewDataProvider()
    {
        return [
            'settings do not require encryption' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => false,
            ],
            'wantNameIdEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'wantAssertionsEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'both settings enabled'=> [
                'alwaysIncludeEncryption' => false,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and wantNameIdEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => false,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and wantAssertionsEncrypted setting enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => false,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
            'metadata requested with encryption and both settings enabled' => [
                'alwaysIncludeEncryption' => true,
                'wantNameIdEncrypted' => true,
                'wantAssertionsEncrypted' => true,
                'expectEncryptionKeyDescriptor' => true,
            ],
        ];
    }

    /**
    * Tests the getSPMetadata method of the OneLogin_Saml2_Settings
    * Case ValidUntil CacheDuration
    *
    * @covers OneLogin\Saml2\Settings::getSPMetadata
    */
    public function testGetSPMetadataTiming()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $currentValidUntil =  time() + Metadata::TIME_VALID;
        $currentValidUntilStr =  gmdate('Y-m-d\TH:i:s\Z', $currentValidUntil);
        $defaultCacheDuration = Metadata::TIME_CACHED;

        $metadata = $settings->getSPMetadata();
        $this->assertContains('validUntil="'.$currentValidUntilStr.'"', $metadata);
        $this->assertContains('cacheDuration="PT604800S"', $metadata);

        $newValidUntil = 2524668343;
        $newValidUntilStr = gmdate('Y-m-d\TH:i:s\Z', $newValidUntil);
        $newCacheDuration = 1209600;
        $metadata2 = $settings->getSPMetadata(false, $newValidUntil, $newCacheDuration);
        $this->assertContains('validUntil="'.$newValidUntilStr.'"', $metadata2);
        $this->assertContains('cacheDuration="PT1209600S"', $metadata2);
    }

    /**
     * Tests the getSPMetadata method of the Settings
     * Case signed metadata
     *
     * @covers OneLogin\Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadataSigned()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = array();
        }
        $settingsInfo['security']['signMetadata'] = true;
        $settings = new Settings($settingsInfo);

        $metadata = $settings->getSPMetadata();

        $this->assertNotEmpty($metadata);

        $this->assertContains('<md:SPSSODescriptor', $metadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata);
        $this->assertContains('WantAssertionsSigned="false"', $metadata);
        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata);
        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertContains('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $metadata);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $metadata);
        $this->assertContains('<ds:Reference', $metadata);
        $this->assertContains('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $metadata);


        include $settingsDir.'settings2.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = array();
        }
        $settingsInfo['security']['signMetadata'] = true;

        $settings2 = new Settings($settingsInfo);

        $metadata2 = $settings2->getSPMetadata();

        $this->assertNotEmpty($metadata2);

        $this->assertContains('<md:SPSSODescriptor', $metadata2);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata2);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata2);
        $this->assertContains('WantAssertionsSigned="false"', $metadata2);
        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata2);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);
        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata2);

        $this->assertContains('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $metadata2);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $metadata2);
        $this->assertContains('<ds:Reference', $metadata2);
        $this->assertContains('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $metadata2);

        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/metadata.crt');
        $settingsInfo['security']['signMetadata'] = [
            'privateKey' => file_get_contents(TEST_ROOT . '/data/customPath/certs/metadata.key'),
            'x509cert' => $cert,
        ];
        $settings3 = new Settings($settingsInfo);
        $metadata3 = $settings3->getSPMetadata();

        $this->assertNotEmpty($metadata3);
        $this->assertContains('<md:SPSSODescriptor', $metadata3);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata3);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata3);
        $this->assertContains('WantAssertionsSigned="false"', $metadata3);
        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://stuff.com/endpoints/endpoints/acs.php" index="1"/>', $metadata3);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata3);
        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata3);

        $this->assertContains('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $metadata3);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $metadata3);
        $this->assertContains('<ds:Reference', $metadata3);
        $this->assertContains('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $metadata3);
        $this->assertContains(Utils::formatCert($cert, false), $metadata3);
    }

    /**
     * Tests the getSPMetadata method of the Settings
     * Case signed metadata with specific certs
     *
     * @covers OneLogin\Saml2\Settings::getSPMetadata
     */
    public function testGetSPMetadataSignedNoMetadataCert()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = array();
        }
        $settingsInfo['security']['signMetadata'] = array();

        try {
            $settings = new Settings($settingsInfo);
            $metadata = $settings->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('sp_signMetadata_invalid', $e->getMessage());
        }


        $settingsInfo['security']['signMetadata'] = array(
            'keyFileName' => 'noexist.key',
            'certFileName' => 'sp.crt'
        );

        $settings = new Settings($settingsInfo);
        try {
            $metadata = $settings->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('Private key file not found', $e->getMessage());
        }

        $settingsInfo['security']['signMetadata'] = array(
            'keyFileName' => 'sp.key',
            'certFileName' => 'noexist.crt'
        );
        $settings = new Settings($settingsInfo);

        try {
            $metadata = $settings->getSPMetadata();
            $this->fail('Error was not raised');
        } catch (Error $e) {
            $this->assertContains('Public cert file not found', $e->getMessage());
        }
    }


    /**
     * Tests the setIdPCert method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::setIdPCert
     */
    public function testSetIdPCert()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $cert = $settingsInfo['idp']['x509cert'];
        $settingsInfo['idp']['certFingerprint'] = 'AF:E7:1C:28:EF:74:0B:C8:74:25:BE:13:A2:26:3D:37:97:1D:A1:F9';
        unset($settingsInfo['idp']['x509cert']);

        $settings = new Settings($settingsInfo);
        $idpData = $settings->getIdPData();
        $this->assertEquals($idpData['x509cert'], '');

        $settings->setIdPCert($cert);
        $idpData2 = $settings->getIdPData();
        $this->assertNotEquals($idpData2['x509cert'], '');
        $this->assertNotEquals($idpData2['x509cert'], $cert);

        $formatedCert = Utils::formatCert($cert);
        $this->assertEquals($idpData2['x509cert'], $formatedCert);
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case valid metadata
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateMetadata()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = $settings->getSPMetadata();

        $this->assertEmpty($settings->validateMetadata($metadata));
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case valid signed metadata
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateSignedMetadata()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml');

        $this->assertEmpty($settings->validateMetadata($metadata));
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case expired metadata
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataExpired()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = file_get_contents(TEST_ROOT . '/data/metadata/expired_metadata_settings1.xml');

        $errors = $settings->validateMetadata($metadata);
        $this->assertNotEmpty($errors);
        $this->assertContains('expired_xml', $errors);
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case no metadata
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataNoXML()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = '';
        try {
            $errors = $settings->validateMetadata($metadata);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Empty string supplied as input', $e->getMessage());
        }

        $metadata = '<no xml>';
        $errors = $settings->validateMetadata($metadata);

        $this->assertNotEmpty($errors);
        $this->assertContains('unloaded_xml', $errors);
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case invalid xml metadata: No entity
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataNoEntity()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = file_get_contents(TEST_ROOT . '/data/metadata/noentity_metadata_settings1.xml');

        $errors = $settings->validateMetadata($metadata);
        $this->assertNotEmpty($errors);
        $this->assertContains('invalid_xml', $errors);
    }

    /**
     * Tests the validateMetadata method of the Settings
     * Case invalid xml metadata: Wrong order
     *
     * @covers OneLogin\Saml2\Settings::validateMetadata
     */
    public function testValidateMetadataWrongOrder()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $metadata = file_get_contents(TEST_ROOT . '/data/metadata/metadata_bad_order_settings1.xml');

        $errors = $settings->validateMetadata($metadata);
        $this->assertNotEmpty($errors);
        $this->assertContains('invalid_xml', $errors);
    }

    /**
     * Tests the getIdPData method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getIdPData
     */
    public function testGetIdPData()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        $this->assertNotEmpty($idpData);
        $this->assertArrayHasKey('entityId', $idpData);
        $this->assertArrayHasKey('singleSignOnService', $idpData);
        $this->assertArrayHasKey('singleLogoutService', $idpData);
        $this->assertArrayHasKey('x509cert', $idpData);

        $this->assertEquals('http://idp.example.com/', $idpData['entityId']);
        $this->assertEquals('http://idp.example.com/SSOService.php', $idpData['singleSignOnService']['url']);
        $this->assertEquals('http://idp.example.com/SingleLogoutService.php', $idpData['singleLogoutService']['url']);
        $x509cert = 'MIICgTCCAeoCCQCbOlrWDdX7FTANBgkqhkiG9w0BAQUFADCBhDELMAkGA1UEBhMCTk8xGDAWBgNVBAgTD0FuZHJlYXMgU29sYmVyZzEMMAoGA1UEBxMDRm9vMRAwDgYDVQQKEwdVTklORVRUMRgwFgYDVQQDEw9mZWlkZS5lcmxhbmcubm8xITAfBgkqhkiG9w0BCQEWEmFuZHJlYXNAdW5pbmV0dC5ubzAeFw0wNzA2MTUxMjAxMzVaFw0wNzA4MTQxMjAxMzVaMIGEMQswCQYDVQQGEwJOTzEYMBYGA1UECBMPQW5kcmVhcyBTb2xiZXJnMQwwCgYDVQQHEwNGb28xEDAOBgNVBAoTB1VOSU5FVFQxGDAWBgNVBAMTD2ZlaWRlLmVybGFuZy5ubzEhMB8GCSqGSIb3DQEJARYSYW5kcmVhc0B1bmluZXR0Lm5vMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDivbhR7P516x/S3BqKxupQe0LONoliupiBOesCO3SHbDrl3+q9IbfnfmE04rNuMcPsIxB161TdDpIesLCn7c8aPHISKOtPlAeTZSnb8QAu7aRjZq3+PbrP5uW3TcfCGPtKTytHOge/OlJbo078dVhXQ14d1EDwXJW1rRXuUt4C8QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBACDVfp86HObqY+e8BUoWQ9+VMQx1ASDohBjwOsg2WykUqRXF+dLfcUH9dWR63CtZIKFDbStNomPnQz7nbK+onygwBspVEbnHuUihZq3ZUdmumQqCw4Uvs/1Uvq3orOo/WJVhTyvLgFVK2QarQ4/67OZfHd7R+POBXhophSMv1ZOo';
        $formatedx509cert = Utils::formatCert($x509cert);
        $this->assertEquals($formatedx509cert, $idpData['x509cert']);

        include $settingsDir.'settings6.php';

        $settings2 = new Settings($settingsInfo);
        $idpData2 = $settings2->getIdPData();
        $this->assertNotEmpty($idpData2);
        $this->assertArrayHasKey('x509certMulti', $idpData2);
        $this->assertArrayHasKey('signing', $idpData2['x509certMulti']);
        $this->assertArrayHasKey('encryption', $idpData2['x509certMulti']);

        $x509cert2 = 'MIICbDCCAdWgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBTMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRgwFgYDVQQDDA9pZHAuZXhhbXBsZS5jb20wHhcNMTQwOTIzMTIyNDA4WhcNNDIwMjA4MTIyNDA4WjBTMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRgwFgYDVQQDDA9pZHAuZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOWA+YHU7cvPOrBOfxCscsYTJB+kH3MaA9BFrSHFS+KcR6cw7oPSktIJxUgvDpQbtfNcOkE/tuOPBDoech7AXfvH6d7Bw7xtW8PPJ2mB5Hn/HGW2roYhxmfh3tR5SdwN6i4ERVF8eLkvwCHsNQyK2Ref0DAJvpBNZMHCpS24916/AgMBAAGjUDBOMB0GA1UdDgQWBBQ77/qVeiigfhYDITplCNtJKZTM8DAfBgNVHSMEGDAWgBQ77/qVeiigfhYDITplCNtJKZTM8DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAJO2j/1uO80E5C2PM6Fk9mzerrbkxl7AZ/mvlbOn+sNZE+VZ1AntYuG8ekbJpJtG1YfRfc7EA9mEtqvv4dhv7zBy4nK49OR+KpIBjItWB5kYvrqMLKBa32sMbgqqUqeF1ENXKjpvLSuPdfGJZA3dNa/+Dyb8GGqWe707zLyc5F8m';
        $formatedx509cert2 = Utils::formatCert($x509cert2);

        $idpCertSign = $idpData2['x509certMulti']['signing'];
        $this->assertEquals($formatedx509cert2, $idpData2['x509certMulti']['signing'][0]);
        $this->assertEquals($formatedx509cert, $idpData2['x509certMulti']['signing'][1]);
        $this->assertEquals($formatedx509cert, $idpData2['x509certMulti']['encryption'][0]);
    }

    /**
     * Tests the getSPData method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getSPData
     */
    public function testGetSPData()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $spData = $settings->getSPData();
        $this->assertNotEmpty($spData);
        $this->assertArrayHasKey('entityId', $spData);
        $this->assertArrayHasKey('assertionConsumerService', $spData);
        $this->assertArrayHasKey('singleLogoutService', $spData);
        $this->assertArrayHasKey('NameIDFormat', $spData);

        $this->assertEquals('http://stuff.com/endpoints/metadata.php', $spData['entityId']);
        $this->assertEquals('http://stuff.com/endpoints/endpoints/acs.php', $spData['assertionConsumerService']['url']);
        $this->assertEquals('http://stuff.com/endpoints/endpoints/sls.php', $spData['singleLogoutService']['url']);
        $this->assertEquals('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', $spData['NameIDFormat']);
    }

    /**
     * Tests the getSecurityData method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getSecurityData
     */
    public function testGetSecurityData()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $security = $settings->getSecurityData();
        $this->assertNotEmpty($security);
        $this->assertArrayHasKey('nameIdEncrypted', $security);
        $this->assertArrayHasKey('authnRequestsSigned', $security);
        $this->assertArrayHasKey('logoutRequestSigned', $security);
        $this->assertArrayHasKey('logoutResponseSigned', $security);
        $this->assertArrayHasKey('signMetadata', $security);
        $this->assertArrayHasKey('wantMessagesSigned', $security);
        $this->assertArrayHasKey('wantAssertionsSigned', $security);
        $this->assertArrayHasKey('wantAssertionsEncrypted', $security);
        $this->assertArrayHasKey('wantNameIdEncrypted', $security);
        $this->assertArrayHasKey('requestedAuthnContext', $security);
        $this->assertArrayHasKey('wantXMLValidation', $security);
        $this->assertArrayHasKey('wantNameId', $security);
        $this->assertArrayHasKey('relaxDestinationValidation', $security);
        $this->assertArrayHasKey('rejectUnsolicitedResponsesWithInResponseTo', $security);
        $this->assertArrayHasKey('destinationStrictlyMatches', $security);
    }

    /**
     * Tests default values of Security advanced sesettings
     *
     * @covers OneLogin\Saml2\Settings::getSecurityData
     */
    public function testGetDefaultSecurityValues()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        unset($settingsInfo['security']);

        $settings = new Settings($settingsInfo);

        $security = $settings->getSecurityData();
        $this->assertNotEmpty($security);

        $this->assertArrayHasKey('nameIdEncrypted', $security);
        $this->assertFalse($security['nameIdEncrypted']);

        $this->assertArrayHasKey('authnRequestsSigned', $security);
        $this->assertFalse($security['authnRequestsSigned']);

        $this->assertArrayHasKey('logoutRequestSigned', $security);
        $this->assertFalse($security['logoutRequestSigned']);

        $this->assertArrayHasKey('logoutResponseSigned', $security);
        $this->assertFalse($security['logoutResponseSigned']);

        $this->assertArrayHasKey('signMetadata', $security);
        $this->assertFalse($security['signMetadata']);

        $this->assertArrayHasKey('wantMessagesSigned', $security);
        $this->assertFalse($security['wantMessagesSigned']);

        $this->assertArrayHasKey('wantAssertionsSigned', $security);
        $this->assertFalse($security['wantAssertionsSigned']);

        $this->assertArrayHasKey('wantAssertionsEncrypted', $security);
        $this->assertFalse($security['wantAssertionsEncrypted']);

        $this->assertArrayHasKey('wantNameIdEncrypted', $security);
        $this->assertFalse($security['wantNameIdEncrypted']);

        $this->assertArrayHasKey('requestedAuthnContext', $security);
        $this->assertTrue($security['requestedAuthnContext']);

        $this->assertArrayHasKey('wantXMLValidation', $security);
        $this->assertTrue($security['wantXMLValidation']);

        $this->assertArrayHasKey('wantNameId', $security);
        $this->assertTrue($security['wantNameId']);
    }

    /**
     * Tests the getContacts method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getContacts
     */
    public function testGetContacts()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $contacts = $settings->getContacts();
        $this->assertNotEmpty($contacts);
        $this->assertEquals('technical_name', $contacts['technical']['givenName']);
        $this->assertEquals('technical@example.com', $contacts['technical']['emailAddress']);
        $this->assertEquals('support_name', $contacts['support']['givenName']);
        $this->assertEquals('support@example.com', $contacts['support']['emailAddress']);
    }

    /**
     * Tests the getOrganization method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::getOrganization
     */
    public function testGetOrganization()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $organization = $settings->getOrganization();
        $this->assertNotEmpty($organization);
        $this->assertEquals('sp_test', $organization['en-US']['name']);
        $this->assertEquals('SP test', $organization['en-US']['displayname']);
        $this->assertEquals('http://sp.example.com', $organization['en-US']['url']);
    }

    /**
     * Tests the setStrict method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::setStrict
     */
    public function testSetStrict()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $this->assertFalse($settings->isStrict());

        $settings->setStrict(false);
        $this->assertFalse($settings->isStrict());

        $settings->setStrict(true);
        $this->assertTrue($settings->isStrict());

        try {
            $settings->setStrict('a');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid value passed to setStrict()', $e->getMessage());
        }
    }

    /**
     * Tests the isStrict method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::isStrict
     */
    public function testIsStrict()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        unset($settingsInfo['strict']);

        $settings = new Settings($settingsInfo);
        $this->assertTrue($settings->isStrict());

        $settingsInfo['strict'] = false;
        $settings2 = new Settings($settingsInfo);
        $this->assertFalse($settings2->isStrict());

        $settingsInfo['strict'] = true;
        $settings3 = new Settings($settingsInfo);
        $this->assertTrue($settings3->isStrict());
    }

    /**
     * Tests the isDebugActive method of the Settings
     *
     * @covers OneLogin\Saml2\Settings::isDebugActive
     */
    public function testIsDebugActive()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';
        unset($settingsInfo['debug']);

        $settings = new Settings($settingsInfo);
        $this->assertFalse($settings->isDebugActive());

        $settingsInfo['debug'] = false;
        $settings2 = new Settings($settingsInfo);
        $this->assertFalse($settings2->isDebugActive());

        $settingsInfo['debug'] = true;
        $settings3 = new Settings($settingsInfo);
        $this->assertTrue($settings3->isDebugActive());
    }
}
