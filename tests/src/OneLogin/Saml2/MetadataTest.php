<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

use Exception;

/**
 * Unit tests for Metadata class
 */
class MetadataTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Tests the builder method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilder()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertNotEmpty($metadata);

        $this->assertStringContainsString('<md:SPSSODescriptor', $metadata);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $metadata);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $metadata);

        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $metadata);
        $this->assertStringContainsString('Location="http://stuff.com/endpoints/endpoints/acs.php"', $metadata);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata);
        $this->assertStringContainsString('Location="http://stuff.com/endpoints/endpoints/sls.php"', $metadata);

        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertStringContainsString('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', $metadata);
        $this->assertStringContainsString('<md:ContactPerson contactType="technical">', $metadata);
        $this->assertStringContainsString('<md:GivenName>technical_name</md:GivenName>', $metadata);
        $this->assertStringContainsString('validUntil', $metadata);

        $security['authnRequestsSigned'] = true;
        $security['wantAssertionsSigned'] = true;
        unset($spData['singleLogoutService']);

        $metadata2 = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata2);

        $this->assertStringContainsString('AuthnRequestsSigned="true"', $metadata2);
        $this->assertStringContainsString('WantAssertionsSigned="true"', $metadata2);

        $this->assertStringNotContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata2);
        $this->assertStringNotContainsString(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);

        $metadata3 = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization, array(), true);
        $this->assertStringNotContainsString('validUntil=', $metadata3);
    }

    /**
     * Tests the builder method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingService()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings3.php';
        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertStringContainsString('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertStringContainsString('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);

        $result = Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd');
        $this->assertInstanceOf('DOMDocument', $result);
    }

    /**
     * Tests the builder method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilderWithAttributeConsumingServiceWithMultipleAttributeValue()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings4.php';
        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertStringContainsString('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertStringContainsString('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertStringContainsString('<md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" isRequired="true" />', $metadata);
        $this->assertStringContainsString('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">userType</saml:AttributeValue>', $metadata);
        $this->assertStringContainsString('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin</saml:AttributeValue>', $metadata);

        $result = Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd');
        $this->assertInstanceOf('DOMDocument', $result);
    }

    /**
     * Tests the signMetadata method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadata()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = Metadata::signMetadata($metadata, $key, $cert);

        $this->assertStringContainsString('<md:SPSSODescriptor', $signedMetadata);
        $this->assertStringContainsString('entityID="http://stuff.com/endpoints/metadata.php"', $signedMetadata);
        $this->assertStringContainsString('AuthnRequestsSigned="false"', $signedMetadata);
        $this->assertStringContainsString('WantAssertionsSigned="false"', $signedMetadata);

        $this->assertStringContainsString('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $signedMetadata);
        $this->assertStringContainsString('Location="http://stuff.com/endpoints/endpoints/acs.php"', $signedMetadata);
        $this->assertStringContainsString('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $signedMetadata);
        $this->assertStringContainsString(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $signedMetadata);

        $this->assertStringContainsString('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $signedMetadata);

        $this->assertStringContainsString('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $signedMetadata);
        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertStringContainsString('<ds:Reference', $signedMetadata);
        $this->assertStringContainsString('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $signedMetadata);

        try {
            $signedMetadata2 = Metadata::signMetadata('', $key, $cert);
            $this->fail('Exception was not raised');
        } catch (\Error | \Exception $e) {
            $expectedErrors = array('DOMDocument::loadXML(): Argument #1 ($source) must not be empty', 'DOMDocument::loadXML(): Empty string supplied as input');
            $this->assertTrue(in_array($e->getMessage(), $expectedErrors));
        }
    }

    /**
     * Tests the signMetadata method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadataDefaultAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = Metadata::signMetadata($metadata, $key, $cert);

        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>', $signedMetadata);
    }

    /**
     * Tests the signMetadata method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::signMetadata
     */
    public function testSignMetadataCustomAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = Metadata::signMetadata($metadata, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);

        $this->assertStringContainsString('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertStringContainsString('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $signedMetadata);
    }

    /**
     * Tests the addX509KeyDescriptors method of the Metadata
     *
     * @covers OneLogin\Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();

        $metadata = Metadata::builder($spData);

        $this->assertStringNotContainsString('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadata);

        $certPath = $settings->getCertPath();
        $cert = file_get_contents($certPath.'sp.crt');

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert);

        $this->assertStringContainsString('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertStringContainsString('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertStringContainsString('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = Metadata::addX509KeyDescriptors($metadata, $cert, 'foobar');

        $this->assertStringContainsString('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        try {
            $signedMetadata2 = Metadata::addX509KeyDescriptors('', $cert);
            $this->fail('Exception was not raised');
        } catch (\Error | \Exception $e) {
            $expectedErrors = array('DOMDocument::loadXML(): Argument #1 ($source) must not be empty', 'Error parsing metadata. DOMDocument::loadXML(): Empty string supplied as input');
            $this->assertTrue(in_array($e->getMessage(), $expectedErrors));
        }

        libxml_use_internal_errors(true);
        $unparsedMetadata = file_get_contents(TEST_ROOT . '/data/metadata/unparsed_metadata.xml');
        try {
            $metadataWithDescriptors = Metadata::addX509KeyDescriptors($unparsedMetadata, $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('Error parsing metadata', $e->getMessage());
        }
    }

    /**
     * Tests the addX509KeyDescriptors method of the Metadata
     * Case: Execute 2 addX509KeyDescriptors calls
     *
     * @covers OneLogin\Saml2\Metadata::addX509KeyDescriptors
     */
    public function testAddX509KeyDescriptors2Times()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $spData = $settings->getSPData();

        $metadata = Metadata::builder($spData);

        $this->assertStringNotContainsString('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertStringNotContainsString('<md:KeyDescriptor use="encryption"', $metadata);

        $certPath = $settings->getCertPath();
        $cert = file_get_contents($certPath.'sp.crt');

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(1, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata = Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(2, substr_count($metadata, "<md:KeyDescriptor"));


        $metadata2 = Metadata::builder($spData);

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(2, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));

        $metadata2 = Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(4, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));
    }

    /**
     * Tests that the values written in the metadata are escaped, so the
     * XML is well formed and has the values of the settings (#674)
     *
     * @covers OneLogin\Saml2\Metadata::builder
     */
    public function testBuilderValuesAreEscaped()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $url = 'https://sp.example.com/endpoint?client=foo&id=bar';
        $text = 'A & B <"quoted"> \'text\'';

        $settingsInfo['sp']['entityId'] = $url . '&e=1';
        $settingsInfo['sp']['assertionConsumerService']['url'] = $url . '&acs=1';
        $settingsInfo['sp']['singleLogoutService']['url'] = $url . '&sls=1';
        $settingsInfo['sp']['NameIDFormat'] = 'urn:example:nameid?a=1&b=2';
        $settingsInfo['sp']['attributeConsumingService'] = array(
            'serviceName' => $text . ' service',
            'serviceDescription' => $text . ' description',
            'requestedAttributes' => array(
                array(
                    'name' => $url . '&attr=1',
                    'nameFormat' => 'urn:example:format?a=1&b=2',
                    'friendlyName' => $text . ' friendly',
                    'isRequired' => true,
                    'attributeValue' => array($text . ' value', $url . '&value=1'),
                ),
            ),
        );
        $settingsInfo['organization'] = array(
            'en-US' => array(
                'name' => $text . ' name',
                'displayname' => $text . ' displayname',
                'url' => $url . '&org=1',
            ),
        );
        $settingsInfo['contactPerson'] = array(
            'technical' => array(
                'givenName' => $text . ' technical',
                'emailAddress' => 'a&b@example.com',
            ),
            'support' => array(
                'givenName' => 'support_name',
                'emailAddress' => 'support@example.com',
            ),
        );

        $settings = new Settings($settingsInfo);
        $metadata = Metadata::builder($settings->getSPData(), false, false, null, null, $settings->getContacts(), $settings->getOrganization());

        $dom = new \DOMDocument();
        $this->assertTrue($dom->loadXML($metadata));
        $xpath = new \DOMXPath($dom);
        $xpath->registerNamespace('md', 'urn:oasis:names:tc:SAML:2.0:metadata');
        $xpath->registerNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion');
        $value = function ($query) use ($xpath) {
            return $xpath->evaluate('string(' . $query . ')');
        };

        $this->assertEquals($url . '&e=1', $value('/md:EntityDescriptor/@entityID'));
        $this->assertEquals($url . '&acs=1', $value('//md:AssertionConsumerService/@Location'));
        $this->assertEquals($url . '&sls=1', $value('//md:SingleLogoutService/@Location'));
        $this->assertEquals('urn:example:nameid?a=1&b=2', $value('//md:NameIDFormat'));

        $this->assertEquals($text . ' service', $value('//md:ServiceName'));
        $this->assertEquals($text . ' description', $value('//md:ServiceDescription'));
        $this->assertEquals($url . '&attr=1', $value('//md:RequestedAttribute/@Name'));
        $this->assertEquals('urn:example:format?a=1&b=2', $value('//md:RequestedAttribute/@NameFormat'));
        $this->assertEquals($text . ' friendly', $value('//md:RequestedAttribute/@FriendlyName'));
        $this->assertEquals($text . ' value', $value('//md:RequestedAttribute/saml:AttributeValue[1]'));
        $this->assertEquals($url . '&value=1', $value('//md:RequestedAttribute/saml:AttributeValue[2]'));

        $this->assertEquals($text . ' name', $value('//md:OrganizationName'));
        $this->assertEquals($text . ' displayname', $value('//md:OrganizationDisplayName'));
        $this->assertEquals($url . '&org=1', $value('//md:OrganizationURL'));

        $this->assertEquals($text . ' technical', $value('//md:ContactPerson[@contactType="technical"]/md:GivenName'));
        $this->assertEquals('a&b@example.com', $value('//md:ContactPerson[@contactType="technical"]/md:EmailAddress'));
        $this->assertEquals('support_name', $value('//md:ContactPerson[@contactType="support"]/md:GivenName'));
    }
}
