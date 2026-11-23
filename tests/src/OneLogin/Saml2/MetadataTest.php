<?php

/**
 * Unit tests for Metadata class
 */
class OneLogin_Saml2_MetadataTest extends PHPUnit_Framework_TestCase
{

    /**
    * Tests the builder method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::builder
    */
    public function testBuilder()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertNotEmpty($metadata);

        $this->assertContains('<md:SPSSODescriptor', $metadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $metadata);
        $this->assertContains('AuthnRequestsSigned="false"', $metadata);
        $this->assertContains('WantAssertionsSigned="false"', $metadata);

        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $metadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/acs.php"', $metadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/sls.php"', $metadata);

        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $metadata);

        $this->assertContains('<md:OrganizationName xml:lang="en-US">sp_test</md:OrganizationName>', $metadata);
        $this->assertContains('<md:ContactPerson contactType="technical">', $metadata);
        $this->assertContains('<md:GivenName>technical_name</md:GivenName>', $metadata);
        $this->assertContains('validUntil', $metadata);

        $security['authnRequestsSigned'] = true;
        $security['wantAssertionsSigned'] = true;
        unset($spData['singleLogoutService']);

        $metadata2 = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata2);

        $this->assertContains('AuthnRequestsSigned="true"', $metadata2);
        $this->assertContains('WantAssertionsSigned="true"', $metadata2);

        $this->assertNotContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $metadata2);
        $this->assertNotContains(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $metadata2);

        $metadata3 = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization, array(), true);
        $this->assertNotContains('validUntil=', $metadata3);
    }

    /**
    * Tests the builder method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::builder
    */
    public function testBuilderWithAttributeConsumingService()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings3.php';
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertContains('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertContains('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="FirstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="LastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" isRequired="true" />', $metadata);

        $result = \OneLogin_Saml2_Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd');
        $this->assertInstanceOf('DOMDocument', $result);
    }

    /**
    * Tests the builder method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::builder
    */
    public function testBuilderWithAttributeConsumingServiceWithMultipleAttributeValue()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings4.php';
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();
        $organization = $settings->getOrganization();
        $contacts = $settings->getContacts();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned'], null, null, $contacts, $organization);

        $this->assertContains('<md:ServiceName xml:lang="en">Service Name</md:ServiceName>', $metadata);
        $this->assertContains('<md:ServiceDescription xml:lang="en">Service Description</md:ServiceDescription>', $metadata);
        $this->assertContains('<md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.1" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="uid" isRequired="true" />', $metadata);
        $this->assertContains('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">userType</saml:AttributeValue>', $metadata);
        $this->assertContains('<saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">admin</saml:AttributeValue>', $metadata);

        $result = \OneLogin_Saml2_Utils::validateXML($metadata, 'saml-schema-metadata-2.0.xsd');
        $this->assertInstanceOf('DOMDocument', $result);
    }

    /**
    * Tests the signMetadata method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::signMetadata
    */
    public function testSignMetadata()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $this->assertNotEmpty($metadata);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = OneLogin_Saml2_Metadata::signMetadata($metadata, $key, $cert);

        $this->assertContains('<md:SPSSODescriptor', $signedMetadata);
        $this->assertContains('entityID="http://stuff.com/endpoints/metadata.php"', $signedMetadata);
        $this->assertContains('AuthnRequestsSigned="false"', $signedMetadata);
        $this->assertContains('WantAssertionsSigned="false"', $signedMetadata);

        $this->assertContains('<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"', $signedMetadata);
        $this->assertContains('Location="http://stuff.com/endpoints/endpoints/acs.php"', $signedMetadata);
        $this->assertContains('<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"', $signedMetadata);
        $this->assertContains(' Location="http://stuff.com/endpoints/endpoints/sls.php"/>', $signedMetadata);

        $this->assertContains('<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>', $signedMetadata);

        $this->assertContains('<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $signedMetadata);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', $signedMetadata);
        $this->assertContains('<ds:Reference', $signedMetadata);
        $this->assertContains('<ds:KeyInfo><ds:X509Data><ds:X509Certificate>', $signedMetadata);

        try {
            $signedMetadata2 = OneLogin_Saml2_Metadata::signMetadata('', $key, $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Empty string supplied as input', $e->getMessage());
        }
    }

    /**
    * Tests the signMetadata method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::signMetadata
    */
    public function testSignMetadataDefaultAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = OneLogin_Saml2_Metadata::signMetadata($metadata, $key, $cert);

        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', $signedMetadata);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>', $signedMetadata);
    }

    /**
    * Tests the signMetadata method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::signMetadata
    */
    public function testSignMetadataCustomAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();
        $security = $settings->getSecurityData();

        $metadata = OneLogin_Saml2_Metadata::builder($spData, $security['authnRequestsSigned'], $security['wantAssertionsSigned']);

        $certPath = $settings->getCertPath();
        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $signedMetadata = OneLogin_Saml2_Metadata::signMetadata($metadata, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);

        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $signedMetadata);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $signedMetadata);
    }

    /**
    * Tests the addX509KeyDescriptors method of the OneLogin_Saml2_Metadata
    *
    * @covers OneLogin_Saml2_Metadata::addX509KeyDescriptors
    */
    public function testAddX509KeyDescriptors()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();

        $metadata = OneLogin_Saml2_Metadata::builder($spData);

        $this->assertNotContains('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadata);

        $certPath = $settings->getCertPath();
        $cert = file_get_contents($certPath.'sp.crt');

        $metadataWithDescriptors = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata, $cert);

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        $metadataWithDescriptors = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata, $cert, 'foobar');

        $this->assertContains('<md:KeyDescriptor use="signing"', $metadataWithDescriptors);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadataWithDescriptors);

        try {
            $signedMetadata2 = OneLogin_Saml2_Metadata::addX509KeyDescriptors('', $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Error parsing metadata', $e->getMessage());
        }

        libxml_use_internal_errors(true);
        $unparsedMetadata = file_get_contents(TEST_ROOT . '/data/metadata/unparsed_metadata.xml');
        try {
            $metadataWithDescriptors = OneLogin_Saml2_Metadata::addX509KeyDescriptors($unparsedMetadata, $cert);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Error parsing metadata', $e->getMessage());
        }
    }

    /**
    * Tests the addX509KeyDescriptors method of the OneLogin_Saml2_Metadata
    * Case: Execute 2 addX509KeyDescriptors calls
    *
    * @covers OneLogin_Saml2_Metadata::addX509KeyDescriptors
    */
    public function testAddX509KeyDescriptors2Times()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spData = $settings->getSPData();

        $metadata = OneLogin_Saml2_Metadata::builder($spData);

        $this->assertNotContains('<md:KeyDescriptor use="signing"', $metadata);
        $this->assertNotContains('<md:KeyDescriptor use="encryption"', $metadata);

        $certPath = $settings->getCertPath();
        $cert = file_get_contents($certPath.'sp.crt');

        $metadata = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(1, substr_count($metadata, "<md:KeyDescriptor"));

        $metadata = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata, $cert, false);

        $this->assertEquals(2, substr_count($metadata, "<md:KeyDescriptor"));


        $metadata2 = OneLogin_Saml2_Metadata::builder($spData);

        $metadata2 = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(2, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(1, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));

        $metadata2 = OneLogin_Saml2_Metadata::addX509KeyDescriptors($metadata2, $cert);

        $this->assertEquals(4, substr_count($metadata2, "<md:KeyDescriptor"));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="signing"'));

        $this->assertEquals(2, substr_count($metadata2, '<md:KeyDescriptor use="encryption"'));
    }

    /**
     * Tests that the values written in the metadata are escaped, so the
     * XML is well formed and has the values of the settings (#674)
     *
     * @covers OneLogin_Saml2_Metadata::builder
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

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $metadata = OneLogin_Saml2_Metadata::builder($settings->getSPData(), false, false, null, null, $settings->getContacts(), $settings->getOrganization());

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
