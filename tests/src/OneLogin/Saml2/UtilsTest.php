<?php

/**
 * Unit tests for Utils class
 *
 * @backupStaticAttributes enabled
 */
class OneLogin_Saml2_UtilsTest extends PHPUnit_Framework_TestCase
{

    /**
    * Tests the t method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::t
    */
/*
    public function testT()
    {
	setlocale(LC_MESSAGES, 'en_US');

        $msg = 'test';
        $translatedMsg = OneLogin_Saml2_Utils::t($msg);
        $this->assertEquals('test', $translatedMsg);

        setlocale(LC_MESSAGES, 'es_ES');

        $translatedMsg = OneLogin_Saml2_Utils::t($msg);
        $this->assertEquals('prueba', $translatedMsg);

        $newmsg = 'test2: %s';
        $translatedMsgArgs = OneLogin_Saml2_Utils::t($newmsg, array('arg'));
        $this->assertEquals('prueba2: arg', $translatedMsgArgs);
    }
*/

    /**
    * Tests the loadXML method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::loadXML
    */
    public function testLoadXML()
    {
        $dom = new DOMDocument();

        $metadataUnloaded = '<xml><EntityDescriptor>';
        try {
            $res1 = OneLogin_Saml2_Utils::loadXML($dom, $metadataUnloaded);
            $this->assertFalse($res1);
        } catch (\Exception $e) {
          $this->assertEquals('DOMDocument::loadXML(): Premature end of data in tag EntityDescriptor line 1 in Entity, line: 1', $e->getMessage());
        }

        $metadataInvalid = file_get_contents(TEST_ROOT .'/data/metadata/noentity_metadata_settings1.xml');
        $res2 = OneLogin_Saml2_Utils::loadXML($dom, $metadataInvalid);
        $this->assertTrue($res2 instanceof DOMDocument);

        $metadataOk = file_get_contents(TEST_ROOT .'/data/metadata/metadata_settings1.xml');
        $res3 = OneLogin_Saml2_Utils::loadXML($dom, $metadataOk);
        $this->assertTrue($res3 instanceof DOMDocument);
    }

    /**
    * Tests the loadXML method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::loadXML
    */
    public function testXMLAttacks()
    {
        $dom = new DOMDocument();

        $attackXXE = '<?xml version="1.0" encoding="ISO-8859-1"?>
                      <!DOCTYPE foo [
                      <!ELEMENT foo ANY >
                      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>';
        try {
            $res = OneLogin_Saml2_Utils::loadXML($dom, $attackXXE);
            $this->assertFalse($res);
        } catch (Exception $e) {
            $this->assertEquals('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        $xmlWithDTD = '<?xml version="1.0"?>
                          <!DOCTYPE results [
                            <!ELEMENT results (result+)>
                            <!ELEMENT result (#PCDATA)>
                          ]>
                          <results>
                            <result>test</result>
                          </results>';
        try {
            $res2 = OneLogin_Saml2_Utils::loadXML($dom, $xmlWithDTD);
            $this->assertFalse($res2);
        } catch (Exception $e) {
            $this->assertEquals('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        $attackXEE = '<?xml version="1.0"?>
                      <!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
                      <results>
                        <result>This result is &harmless;</result>
                      </results>';
        try {
            $res3 = OneLogin_Saml2_Utils::loadXML($dom, $attackXEE);
            $this->assertFalse($res3);
        } catch (Exception $e) {
            $this->assertEquals('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }

        $attackXEEutf16 = mb_convert_encoding(
            '<?xml version="1.0" encoding="UTF-16"?>
                      <!DOCTYPE results [<!ENTITY harmless "completely harmless">]>
                      <results>
                        <result>This result is &harmless;</result>
                      </results>',
            'UTF-16'
        );
        try {
            $res4 = OneLogin_Saml2_Utils::loadXML($dom, $attackXEEutf16);
            $this->assertFalse($res4);
        } catch (Exception $e) {
            $this->assertEquals('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }
    }

    /**
    * Tests the validateXML method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::validateXML
    */
    public function testValidateXML()
    {
        $metadataUnloaded = '<xml><EntityDescriptor>';
        $this->assertEquals(OneLogin_Saml2_Utils::validateXML($metadataUnloaded, 'saml-schema-metadata-2.0.xsd'), 'unloaded_xml');

        $metadataInvalid = file_get_contents(TEST_ROOT .'/data/metadata/noentity_metadata_settings1.xml');
        $this->assertEquals(OneLogin_Saml2_Utils::validateXML($metadataInvalid, 'saml-schema-metadata-2.0.xsd'), 'invalid_xml');

        $metadataExpired = file_get_contents(TEST_ROOT .'/data/metadata/expired_metadata_settings1.xml');
        $res = OneLogin_Saml2_Utils::validateXML($metadataExpired, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res instanceof DOMDocument);

        $metadataOk = file_get_contents(TEST_ROOT .'/data/metadata/metadata_settings1.xml');
        $res2 = OneLogin_Saml2_Utils::validateXML($metadataOk, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res2 instanceof DOMDocument);

        $metadataBadOrder = file_get_contents(TEST_ROOT .'/data/metadata/metadata_bad_order_settings1.xml');
        $res3 = OneLogin_Saml2_Utils::validateXML($metadataBadOrder, 'saml-schema-metadata-2.0.xsd');
        $this->assertFalse($res3 instanceof DOMDocument);

        $metadataSigned = file_get_contents(TEST_ROOT .'/data/metadata/signed_metadata_settings1.xml');
        $res4 = OneLogin_Saml2_Utils::validateXML($metadataSigned, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res4 instanceof DOMDocument);

        $dom = new DOMDocument;
        OneLogin_Saml2_Utils::loadXML($dom, $metadataOk);
        $res5 = OneLogin_Saml2_Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res5 instanceof DOMDocument);
    }

    /**
    * Tests the formatCert method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::formatCert
    */
    public function testFormatCert()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $cert = $settingsInfo['idp']['x509cert'];
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertNotContains('-----END CERTIFICATE-----', $cert);
        $this->assertEquals(strlen($cert), 860);

        $formatedCert1 = OneLogin_Saml2_Utils::formatCert($cert);
        $this->assertContains('-----BEGIN CERTIFICATE-----', $formatedCert1);
        $this->assertContains('-----END CERTIFICATE-----', $formatedCert1);

        $formatedCert2 = OneLogin_Saml2_Utils::formatCert($cert, true);
        $this->assertEquals($formatedCert1, $formatedCert2);


        $formatedCert3 = OneLogin_Saml2_Utils::formatCert($cert, false);
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $formatedCert3);
        $this->assertNotContains('-----END CERTIFICATE-----', $formatedCert3);
        $this->assertEquals(strlen($cert), 860);


        $cert2 = $settingsInfo['sp']['x509cert'];
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertNotContains('-----END CERTIFICATE-----', $cert);
        $this->assertEquals(strlen($cert), 860);

        $formatedCert4 = OneLogin_Saml2_Utils::formatCert($cert);
        $this->assertContains('-----BEGIN CERTIFICATE-----', $formatedCert4);
        $this->assertContains('-----END CERTIFICATE-----', $formatedCert4);

        $formatedCert5 = OneLogin_Saml2_Utils::formatCert($cert, true);
        $this->assertEquals($formatedCert4, $formatedCert5);


        $formatedCert6 = OneLogin_Saml2_Utils::formatCert($cert, false);
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $formatedCert6);
        $this->assertNotContains('-----END CERTIFICATE-----', $formatedCert6);
        $this->assertEquals(strlen($cert2), 860);

        $cert = file_get_contents(TEST_ROOT.'/certs/with.comment.crt');
        $formatedCert7 = OneLogin_Saml2_Utils::formatCert($cert, true);
        $this->assertContains('-----BEGIN CERTIFICATE-----', $formatedCert7);
        $this->assertContains('-----END CERTIFICATE-----', $formatedCert7);
        $this->assertNotContains('comments', $formatedCert7);
    }

    /**
    * Tests the formatPrivateKey method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::formatPrivateKey
    */
    public function testFormatPrivateKey()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $key = $settingsInfo['sp']['privateKey'];

        $this->assertNotContains('-----BEGIN RSA PRIVATE KEY-----', $key);
        $this->assertNotContains('-----END RSA PRIVATE KEY-----', $key);
        $this->assertEquals(strlen($key), 816);

        $formatedKey1 = OneLogin_Saml2_Utils::formatPrivateKey($key);
        $this->assertContains('-----BEGIN RSA PRIVATE KEY-----', $formatedKey1);
        $this->assertContains('-----END RSA PRIVATE KEY-----', $formatedKey1);

        $formatedKey2 = OneLogin_Saml2_Utils::formatPrivateKey($key, true);
        $this->assertEquals($formatedKey1, $formatedKey2);


        $formatedKey3 = OneLogin_Saml2_Utils::formatPrivateKey($key, false);

        $this->assertNotContains('-----BEGIN RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertNotContains('-----END RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertEquals(strlen($key), 816);
    }

    /**
    * Tests the redirect method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::redirect
    */
    public function testRedirect()
    {
        $_SERVER['HTTP_HOST'] = 'example.com';
        // Check relative and absolute
        $hostname = OneLogin_Saml2_Utils::getSelfHost();
        $url = "http://$hostname/example";
        $url2 = '/example';

        $targetUrl = OneLogin_Saml2_Utils::redirect($url, array(), true);
        $targetUrl2 = OneLogin_Saml2_Utils::redirect($url2, array(), true);

        $this->assertEquals($targetUrl, $targetUrl2);

        // Check that accept http/https and reject other protocols
        $url3 = "https://$hostname/example?test=true";
        $url4 = "ftp://$hostname/example";

        $targetUrl3 = OneLogin_Saml2_Utils::redirect($url3, array(), true);

        try {
            $targetUrl4 = OneLogin_Saml2_Utils::redirect($url4, array(), true);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Redirect to invalid URL', $e->getMessage());
        }

        // Review parameter prefix
        $parameters1 = array ('value1' => 'a');

        $targetUrl5 = OneLogin_Saml2_Utils::redirect($url, $parameters1, true);
        $this->assertEquals("http://$hostname/example?value1=a", $targetUrl5);

        $targetUrl6 = OneLogin_Saml2_Utils::redirect($url3, $parameters1, true);
        $this->assertEquals("https://$hostname/example?test=true&value1=a", $targetUrl6);

        // Review parameters
        $parameters2 = array (
            'alphavalue' => 'a',
            'numvalue' => array ('1', '2'),
            'testing' => null,
        );

        $targetUrl7 = OneLogin_Saml2_Utils::redirect($url, $parameters2, true);
        $this->assertEquals("http://$hostname/example?alphavalue=a&numvalue[]=1&numvalue[]=2&testing", $targetUrl7);

        $parameters3 = array (
            'alphavalue' => 'a',
            'emptynumvaluelist' => array (),
            'numvaluelist' => array (''),
        );

        $targetUrl8 = OneLogin_Saml2_Utils::redirect($url, $parameters3, true);
        $this->assertEquals("http://$hostname/example?alphavalue=a&numvaluelist[]=", $targetUrl8);
    }

    /**
     * @covers OneLogin_Saml2_Utils::setSelfHost
     */
    public function testSetselfhost()
    {
        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertEquals('example.org', OneLogin_Saml2_Utils::getSelfHost());

        OneLogin_Saml2_Utils::setSelfHost('example.com');
        $this->assertEquals('example.com', OneLogin_Saml2_Utils::getSelfHost());
    }

    /**
     * @covers OneLogin_Saml2_Utils::setProxyVars()
     * @covers OneLogin_Saml2_Utils::getProxyVars()
     */
    public function testProxyvars()
    {
        $this->assertFalse(OneLogin_Saml2_Utils::getProxyVars());

        OneLogin_Saml2_Utils::setProxyVars(true);
        $this->assertTrue(OneLogin_Saml2_Utils::getProxyVars());

        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
        $_SERVER['SERVER_PORT'] = '80';

        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());

        OneLogin_Saml2_Utils::setProxyVars(false);
        $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());
    }

    /**
    * Tests the getSelfHost method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getSelfHost
    */
    public function testGetselfhost()
    {
        if (function_exists('gethostname')) {
            $hostname = gethostname();
        } else {
            $hostname = php_uname("n");
        }

        $this->assertEquals($hostname, OneLogin_Saml2_Utils::getSelfHost());

        $_SERVER['SERVER_NAME'] = 'example.com';
        $this->assertEquals('example.com', OneLogin_Saml2_Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertEquals('example.org', OneLogin_Saml2_Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:443';
        $this->assertEquals('example.org', OneLogin_Saml2_Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertEquals('example.org', OneLogin_Saml2_Utils::getSelfHost());

        $_SERVER['HTTP_X_FORWARDED_HOST'] = 'example.net';
        $this->assertNotEquals('example.net', OneLogin_Saml2_Utils::getSelfHost());

        OneLogin_Saml2_Utils::setProxyVars(true);
        $this->assertEquals('example.net', OneLogin_Saml2_Utils::getSelfHost());
    }

    /**
    * Tests the isHTTPS method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::isHTTPS
    */
    public function testisHTTPS()
    {
        $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());

        $_SERVER['HTTPS'] = 'on';
        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());

        unset($_SERVER['HTTPS']);
        $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());
        $_SERVER['HTTP_HOST'] = 'example.com:443';
        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());
    }

    /**
     * @covers OneLogin_Saml2_Utils::getSelfURLhost
     */
    public function testGetselfurlhostdoubleport()
    {
        OneLogin_Saml2_Utils::setProxyVars(true);
        $_SERVER['HTTP_HOST'] = 'example.com:8080';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertEquals('http://example.com:82', OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['HTTP_HOST'] = 'example.com:ok';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertEquals('http://example.com:82', OneLogin_Saml2_Utils::getSelfURLhost());
    }

    /**
     * @covers OneLogin_Saml2_Utils::getSelfPort
     */
    public function testGetselfPort()
    {
        $this->assertNull(OneLogin_Saml2_Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertNull(OneLogin_Saml2_Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:8080';
        $this->assertSame(8080, OneLogin_Saml2_Utils::getSelfPort());

        $_SERVER["SERVER_PORT"] = 80;
        $this->assertSame(80, OneLogin_Saml2_Utils::getSelfPort());

        $_SERVER["HTTP_X_FORWARDED_PORT"] = 443;
        $this->assertSame(80, OneLogin_Saml2_Utils::getSelfPort());

        OneLogin_Saml2_Utils::setProxyVars(true);
        $this->assertSame(443, OneLogin_Saml2_Utils::getSelfPort());

        OneLogin_Saml2_Utils::setSelfPort(8080);
        $this->assertSame(8080, OneLogin_Saml2_Utils::getSelfPort());
    }

    /**
     * getSelfPort returns an integer (or null) whatever the type of the value that it reads.
     * The values of $_SERVER are strings, but the port can also be an integer (setSelfPort(443),
     * or code that sets it at $_SERVER), and a value that is not a port number is not a port
     *
     * @covers OneLogin_Saml2_Utils::getSelfPort
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfPortReturnsAnInteger()
    {
        $valid = array(
            array('80', 80),
            array(80, 80),
            array('443', 443),
            array(443, 443),
            array('8080', 8080),
            array(8080, 8080),
            array(' 8443 ', 8443),
            array('1', 1),
            array('65535', 65535),
        );
        $invalid = array('', ' ', '0', 0, '-1', '65536', '99999999999999999999', 'abc', '443abc', '443.5', '1e3', '0x1bb', '8080, 8081');

        // Where the port is read from
        $sources = array(
            'SERVER_PORT' => function ($port) {
                $_SERVER['SERVER_PORT'] = $port;
            },
            'X-Forwarded-Port' => function ($port) {
                OneLogin_Saml2_Utils::setProxyVars(true);
                $_SERVER['HTTP_X_FORWARDED_PORT'] = $port;
            },
            'Host header' => function ($port) {
                $_SERVER['HTTP_HOST'] = 'example.org:' . $port;
            },
            'setSelfPort' => function ($port) {
                OneLogin_Saml2_Utils::setSelfPort($port);
            },
        );
        $reset = function () {
            unset($_SERVER['SERVER_PORT'], $_SERVER['HTTP_X_FORWARDED_PORT'], $_SERVER['HTTP_HOST']);
            OneLogin_Saml2_Utils::setBaseURL(null);
            OneLogin_Saml2_Utils::setProxyVars(false);
        };

        foreach ($sources as $name => $setPort) {
            foreach ($valid as $case) {
                list($port, $expected) = $case;
                $reset();
                $setPort($port);
                $this->assertSame($expected, OneLogin_Saml2_Utils::getSelfPort(), "$name: " . var_export($port, true));
            }
            foreach ($invalid as $port) {
                $reset();
                $setPort($port);
                $this->assertNull(OneLogin_Saml2_Utils::getSelfPort(), "$name: " . var_export($port, true));
            }
        }
    }

    /**
     * The URL of the host does not have the port when it is the default one of HTTP or HTTPS,
     * whether the port is an integer or a string (the strings come from $_SERVER and from the
     * base URL), and it has the port when it is another one
     *
     * @covers OneLogin_Saml2_Utils::getSelfURLhost
     * @covers OneLogin_Saml2_Utils::getSelfURLNoQuery
     * @covers OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery
     * @covers OneLogin_Saml2_Utils::getSelfURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURLhostWithAPortOfAnyType()
    {
        OneLogin_Saml2_Utils::setSelfHost('example.test');

        $cases = array(
            array('https', 443, 'https://example.test'),
            array('https', '443', 'https://example.test'),
            array('http', 80, 'http://example.test'),
            array('http', '80', 'http://example.test'),
            array('https', 8443, 'https://example.test:8443'),
            array('https', '8443', 'https://example.test:8443'),
            array('http', 8080, 'http://example.test:8080'),
            array('http', '8080', 'http://example.test:8080'),
            // A value that is not a port is not added to the URL
            array('https', 'abc', 'https://example.test'),
            array('https', '443abc', 'https://example.test'),
        );
        foreach ($cases as $case) {
            list($protocol, $port, $expected) = $case;
            OneLogin_Saml2_Utils::setSelfProtocol($protocol);
            OneLogin_Saml2_Utils::setSelfPort($port);
            $this->assertSame($expected, OneLogin_Saml2_Utils::getSelfURLhost(), $protocol . ' ' . var_export($port, true));
        }

        // The port of the request, or the one that a proxy sends
        OneLogin_Saml2_Utils::setSelfProtocol('https');
        OneLogin_Saml2_Utils::setSelfPort(null);
        foreach (array(443, '443') as $port) {
            $_SERVER['SERVER_PORT'] = $port;
            $this->assertSame('https://example.test', OneLogin_Saml2_Utils::getSelfURLhost(), 'SERVER_PORT ' . var_export($port, true));
        }
        foreach (array(8443, '8443') as $port) {
            $_SERVER['SERVER_PORT'] = $port;
            $this->assertSame('https://example.test:8443', OneLogin_Saml2_Utils::getSelfURLhost(), 'SERVER_PORT ' . var_export($port, true));
        }

        OneLogin_Saml2_Utils::setProxyVars(true);
        $_SERVER['SERVER_PORT'] = '8080';
        foreach (array(443, '443') as $port) {
            $_SERVER['HTTP_X_FORWARDED_PORT'] = $port;
            $this->assertSame('https://example.test', OneLogin_Saml2_Utils::getSelfURLhost(), 'X-Forwarded-Port ' . var_export($port, true));
        }
        OneLogin_Saml2_Utils::setProxyVars(false);

        // The URLs that are compared with the one that the IdP sent (the Destination, #661)
        OneLogin_Saml2_Utils::setSelfProtocol('https');
        OneLogin_Saml2_Utils::setSelfPort(443);
        $_SERVER['REQUEST_URI'] = '/admin/saml/acs?x=1';
        $_SERVER['QUERY_STRING'] = 'x=1';
        $_SERVER['SCRIPT_NAME'] = '/admin/saml/acs';
        unset($_SERVER['PATH_INFO']);
        $this->assertSame('https://example.test/admin/saml/acs', OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertSame('https://example.test/admin/saml/acs', OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertSame('https://example.test/admin/saml/acs?x=1', OneLogin_Saml2_Utils::getSelfURL());
    }

    /**
     * The protocol is https when the port is 443, whatever the type of the port
     *
     * @covers OneLogin_Saml2_Utils::getSelfProtocol
     * @covers OneLogin_Saml2_Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfProtocolWithAPortOfAnyType()
    {
        foreach (array(443, '443') as $port) {
            $_SERVER['SERVER_PORT'] = $port;
            $this->assertSame('https', OneLogin_Saml2_Utils::getSelfProtocol(), 'SERVER_PORT ' . var_export($port, true));
            $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());
        }
        foreach (array(80, '80', 8443, '8443', 'abc') as $port) {
            $_SERVER['SERVER_PORT'] = $port;
            $this->assertSame('http', OneLogin_Saml2_Utils::getSelfProtocol(), 'SERVER_PORT ' . var_export($port, true));
            $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());
        }

        unset($_SERVER['SERVER_PORT']);
        foreach (array(443, '443') as $port) {
            OneLogin_Saml2_Utils::setSelfPort($port);
            $this->assertSame('https', OneLogin_Saml2_Utils::getSelfProtocol(), 'setSelfPort ' . var_export($port, true));
        }
    }

    /**
     * @covers OneLogin_Saml2_Utils::setSelfProtocol
     */
    public function testSetselfprotocol()
    {
        $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());

        OneLogin_Saml2_Utils::setSelfProtocol('https');
        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());
    }

    /**
     * A bool is accepted by setSelfProtocol too (setSelfProtocol($isSecure)): true is https, and false
     * is ignored as any empty value, so the protocol is guessed
     *
     * @covers OneLogin_Saml2_Utils::setSelfProtocol
     * @covers OneLogin_Saml2_Utils::getSelfProtocol
     * @covers OneLogin_Saml2_Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetSelfProtocolWithABool()
    {
        OneLogin_Saml2_Utils::setSelfProtocol(true);
        $this->assertSame('https', OneLogin_Saml2_Utils::getSelfProtocol());
        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());

        OneLogin_Saml2_Utils::setSelfProtocol(false);
        $this->assertSame('http', OneLogin_Saml2_Utils::getSelfProtocol());
        $this->assertFalse(OneLogin_Saml2_Utils::isHTTPS());
        $_SERVER['HTTPS'] = 'on';
        $this->assertSame('https', OneLogin_Saml2_Utils::getSelfProtocol());
        $this->assertTrue(OneLogin_Saml2_Utils::isHTTPS());
    }

    /**
     * Checks the protocol and isHTTPS when the value comes from the header that a proxy sends and when the
     * application sets it, and that the toolkit does not raise any PHP error with it
     *
     * @param mixed  $value            The value of the protocol
     * @param string $expectedProtocol The protocol that is expected
     * @param bool   $expectedIsHttps  The value of isHTTPS that is expected
     * @param string $name             The name of the case
     */
    private function assertSelfProtocol($value, $expectedProtocol, $expectedIsHttps, $name)
    {
        $reset = function () {
            OneLogin_Saml2_Utils::setBaseURL(null);
            OneLogin_Saml2_Utils::setProxyVars(false);
            unset($_SERVER['HTTP_X_FORWARDED_PROTO']);
        };
        $protocol = function () {
            return array(OneLogin_Saml2_Utils::getSelfProtocol(), OneLogin_Saml2_Utils::isHTTPS());
        };
        $expected = array($expectedProtocol, $expectedIsHttps);

        // The protocol that a proxy sends
        $reset();
        OneLogin_Saml2_Utils::setProxyVars(true);
        $_SERVER['HTTP_X_FORWARDED_PROTO'] = $value;
        $this->assertSame($expected, $this->withPhpErrorsAsExceptions($protocol), "X-Forwarded-Proto: $name");

        // The protocol that the application sets
        $reset();
        OneLogin_Saml2_Utils::setSelfProtocol($value);
        $this->assertSame($expected, $this->withPhpErrorsAsExceptions($protocol), "setSelfProtocol: $name");

        $reset();
    }

    /**
     * A value that is not a string is not a protocol: it is http, and the toolkit does not raise any PHP
     * error with it (the protocol that comes from $_SERVER is a string, but the one that the application
     * sets can be anything)
     *
     * @covers OneLogin_Saml2_Utils::getSelfProtocol
     * @covers OneLogin_Saml2_Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfProtocolWithAValueThatIsNotAString()
    {
        $values = array(
            'false' => false,
            'integer' => 443,
            'zero' => 0,
            'float' => 1.5,
            'object' => new stdClass(),
            'object with __toString' => new SplFileInfo('https'),
        );
        foreach ($values as $name => $value) {
            $this->assertSelfProtocol($value, 'http', false, $name);
        }

        // Control: a string is the protocol
        $this->assertSelfProtocol('https', 'https', true, 'https');
        $this->assertSelfProtocol('http', 'http', false, 'http');
    }

    /**
     * When the value is an array (the values of a header, as PSR-7 returns them) the protocol is the first one
     *
     * @covers OneLogin_Saml2_Utils::getSelfProtocol
     * @covers OneLogin_Saml2_Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfProtocolWithAnArray()
    {
        $this->assertSelfProtocol(array('https'), 'https', true, 'one value');
        $this->assertSelfProtocol(array('http'), 'http', false, 'one value, http');
        $this->assertSelfProtocol(array('https', 'http'), 'https', true, 'the first value is https');
        $this->assertSelfProtocol(array('http', 'https'), 'http', false, 'only the first value is used');
        $this->assertSelfProtocol(array('proto' => 'https'), 'https', true, 'the first value of an associative array');

        // The first value has to be a string, as any other value
        $this->assertSelfProtocol(array(), 'http', false, 'empty array');
        $this->assertSelfProtocol(array(443), 'http', false, 'the first value is an integer');
        $this->assertSelfProtocol(array(array('https')), 'http', false, 'the first value is an array');
        $this->assertSelfProtocol(array(new SplFileInfo('https')), 'http', false, 'the first value is an object');
        $this->assertSelfProtocol(array(443, 'https'), 'http', false, 'an https value after the first one');
    }

    /**
     * @covers OneLogin_Saml2_Utils::setBaseURLPath
     */
    public function testSetBaseURLPath()
    {
        $this->assertNull(OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('/');
        $this->assertEquals('/', OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('sp');
        $this->assertEquals('/sp/', OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('sp/');
        $this->assertEquals('/sp/', OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('/sp');
        $this->assertEquals('/sp/', OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('/sp/');
        $this->assertEquals('/sp/', OneLogin_Saml2_Utils::getBaseURLPath());
    }

    /**
     * @covers OneLogin_Saml2_Utils::setBaseURLPath
     */
    public function testSetBaseURLPath2()
    {
        $_SERVER['HTTP_HOST'] = 'sp.example.com';
        $_SERVER['HTTPS'] = 'https';
        $_SERVER['REQUEST_URI'] = null;
        $_SERVER['QUERY_STRING'] = null;
        $_SERVER['SCRIPT_NAME'] = '/';
        unset($_SERVER['PATH_INFO']);

        OneLogin_Saml2_Utils::setBaseURLPath('/');
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/', OneLogin_Saml2_Utils::getBaseURLPath());
    }

    /**
     * @covers OneLogin_Saml2_Utils::setBaseURL
     */
    public function testSetBaseURL()
    {
        $_SERVER['HTTP_HOST'] = 'sp.example.com';
        $_SERVER['HTTPS'] = 'https';
        $_SERVER['REQUEST_URI'] = '/example1/route.php?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';
        $_SERVER['SCRIPT_NAME'] = '/example1/route.php';
        unset($_SERVER['PATH_INFO']);

        $expectedUrlNQ = 'https://sp.example.com/example1/route.php';
        $expectedRoutedUrlNQ = 'https://sp.example.com/example1/route.php';
        $expectedUrl = 'https://sp.example.com/example1/route.php?x=test';

        OneLogin_Saml2_Utils::setBaseURL("no-valid-url");
        $this->assertEquals('https', OneLogin_Saml2_Utils::getSelfProtocol());
        $this->assertEquals('sp.example.com', OneLogin_Saml2_Utils::getSelfHost());
        $this->assertNull(OneLogin_Saml2_Utils::getSelfPort());
        $this->assertNull(OneLogin_Saml2_Utils::getBaseURLPath());

        $this->assertEquals($expectedUrlNQ, OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ, OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl, OneLogin_Saml2_Utils::getSelfURL());

        OneLogin_Saml2_Utils::setBaseURL("http://anothersp.example.com:81/example2/");
        $expectedUrlNQ2 = 'http://anothersp.example.com:81/example2/example1/route.php';
        $expectedRoutedUrlNQ2 = 'http://anothersp.example.com:81/example2/example1/route.php';
        $expectedUrl2 = 'http://anothersp.example.com:81/example2/example1/route.php?x=test';

        $this->assertEquals('http', OneLogin_Saml2_Utils::getSelfProtocol());
        $this->assertEquals('anothersp.example.com', OneLogin_Saml2_Utils::getSelfHost());
        $this->assertSame(81, OneLogin_Saml2_Utils::getSelfPort());
        $this->assertEquals('/example2/', OneLogin_Saml2_Utils::getBaseURLPath());

        $this->assertEquals($expectedUrlNQ2, OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ2, OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl2, OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['PATH_INFO'] = '/test';
        $expectedUrlNQ2 = 'http://anothersp.example.com:81/example2/example1/route.php/test';

        $this->assertEquals($expectedUrlNQ2, OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ2, OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl2, OneLogin_Saml2_Utils::getSelfURL());

        OneLogin_Saml2_Utils::setBaseURL("http://anothersp.example.com:81/example2");
        $this->assertEquals($expectedUrlNQ2, OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ2, OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl2, OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/example2/', OneLogin_Saml2_Utils::getBaseURLPath());

        $_SERVER['PATH_INFO'] = null;
        $_SERVER['REQUEST_URI'] = null;
        $_SERVER['QUERY_STRING'] = null;
        $_SERVER['SCRIPT_NAME'] = '/';
        OneLogin_Saml2_Utils::setBaseURL("https://sp.example.com/");
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/', OneLogin_Saml2_Utils::getBaseURLPath());
    }

    /**
     * The port of the base URL is an integer: the one that it has, or the default one of its protocol
     * (the default ports are not part of the URLs that are built)
     *
     * @covers OneLogin_Saml2_Utils::setBaseURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetBaseURLPort()
    {
        $cases = array(
            array('https://sp.example.com', 'https', 443, 'https://sp.example.com'),
            array('http://sp.example.com', 'http', 80, 'http://sp.example.com'),
            array('https://sp.example.com:443/path/', 'https', 443, 'https://sp.example.com'),
            array('http://sp.example.com:80/path/', 'http', 80, 'http://sp.example.com'),
            array('https://sp.example.com:8443/path/', 'https', 8443, 'https://sp.example.com:8443'),
            array('http://sp.example.com:8080', 'http', 8080, 'http://sp.example.com:8080'),
            // A port that is not valid is ignored, the default one of the protocol is used
            array('https://sp.example.com:abc/path/', 'https', 443, 'https://sp.example.com'),
            array('http://sp.example.com:/path/', 'http', 80, 'http://sp.example.com'),
            array('https://sp.example.com:99999/path/', 'https', 443, 'https://sp.example.com'),
        );
        foreach ($cases as $case) {
            list($baseURL, $protocol, $port, $expectedHost) = $case;
            OneLogin_Saml2_Utils::setBaseURL($baseURL);
            $this->assertSame($protocol, OneLogin_Saml2_Utils::getSelfProtocol(), $baseURL);
            $this->assertSame($port, OneLogin_Saml2_Utils::getSelfPort(), $baseURL);
            $this->assertSame($expectedHost, OneLogin_Saml2_Utils::getSelfURLhost(), $baseURL);
        }
    }

    /**
     * @covers OneLogin_Saml2_Utils::setBaseURL
     */
    public function testSetBaseURL2()
    {
        $_SERVER['HTTP_HOST'] = 'sp.example.com';
        $_SERVER['HTTPS'] = 'https';
        $_SERVER['REQUEST_URI'] = null;
        $_SERVER['QUERY_STRING'] = null;
        $_SERVER['SCRIPT_NAME'] = '/';
        unset($_SERVER['PATH_INFO']);

        OneLogin_Saml2_Utils::setBaseURL('https://sp.example.com');
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/', OneLogin_Saml2_Utils::getBaseURLPath());

        $_SERVER['REQUEST_URI'] = '/example1/path/route.php?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';
        $_SERVER['SCRIPT_NAME'] = '/example1/path/route.php';
        $this->assertEquals("https://sp.example.com/example1/path/route.php", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route.php", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route.php?x=test", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/', OneLogin_Saml2_Utils::getBaseURLPath());

        OneLogin_Saml2_Utils::setBaseURLPath('/example1/path/');
        $this->assertEquals("https://sp.example.com/example1/path/route.php", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route.php", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route.php?x=test", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/example1/path/', OneLogin_Saml2_Utils::getBaseURLPath());

        $_SERVER['REQUEST_URI'] = '/example1/path/route/?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';
        $_SERVER['SCRIPT_NAME'] = '/example1/path/route';
        $this->assertEquals("https://sp.example.com/example1/path/route", OneLogin_Saml2_Utils::getSelfURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route", OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals("https://sp.example.com/example1/path/route/?x=test", OneLogin_Saml2_Utils::getSelfURL());
        $this->assertEquals('/example1/path/', OneLogin_Saml2_Utils::getBaseURLPath());
    }

    /**
    * Tests the getSelfURLhost method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getSelfURLhost
    */
    public function testGetSelfURLhost()
    {
        $hostname = OneLogin_Saml2_Utils::getSelfHost();

        $this->assertEquals("http://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '80';
        $this->assertEquals("http://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '81';
        $this->assertEquals("http://$hostname:81", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $this->assertEquals("https://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());

        unset($_SERVER['SERVER_PORT']);
        $_SERVER['HTTPS'] = 'on';
        $this->assertEquals("https://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '444';
        $this->assertEquals("https://$hostname:444", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['REQUEST_URI'] = '/onelogin';
        $this->assertEquals("https://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());

        $_SERVER['REQUEST_URI'] = 'https://$hostname/onelogin/sso';
        $this->assertEquals("https://$hostname", OneLogin_Saml2_Utils::getSelfURLhost());
    }

    /**
    * Tests the getSelfURL method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getSelfURL
    */
    public function testGetSelfURL()
    {
        $url = OneLogin_Saml2_Utils::getSelfURLhost();

        $this->assertEquals($url, OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/index.php';
        $this->assertEquals($url.'/index.php', OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertEquals($url.'/test/index.php?testing', OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertEquals($url.'/test/index.php?testing', OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = 'https://example.com/testing';
        $this->assertEquals($url.'/testing', OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = 'https://example.com/test/';
        $this->assertEquals($url.'/test/', OneLogin_Saml2_Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = 'https://example.com/';
        $this->assertEquals($url.'/', OneLogin_Saml2_Utils::getSelfURL());

    }

    /**
    * Tests the getSelfURLNoQuery method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getSelfURLNoQuery
    */
    public function testGetSelfURLNoQuery()
    {
        $url = OneLogin_Saml2_Utils::getSelfURLhost();
        $url .= $_SERVER['SCRIPT_NAME'];

        $this->assertEquals($url, OneLogin_Saml2_Utils::getSelfURLNoQuery());

        $_SERVER['PATH_INFO'] = '/test';
        $this->assertEquals($url.'/test', OneLogin_Saml2_Utils::getSelfURLNoQuery());
    }

    /**
    * Tests the getSelfRoutedURLNoQuery method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery
    */
    public function getSelfRoutedURLNoQuery()
    {
        $url = OneLogin_Saml2_Utils::getSelfURLhost();
        $_SERVER['REQUEST_URI'] = 'example1/route?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';

        $url .= 'example1/route';

        $this->assertEquals($url, OneLogin_Saml2_Utils::getSelfRoutedURLNoQuery());
    }

    /**
    * Gets the status of a message
    *
    * @covers OneLogin_Saml2_Utils::getStatus
    */
    public function testGetStatus()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64'));
        $dom = new DOMDocument();
        $dom->loadXML($xml);

        $status = OneLogin_Saml2_Utils::getStatus($dom);
        $this->assertEquals(OneLogin_Saml2_Constants::STATUS_SUCCESS, $status['code']);

        $xml2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64'));
        $dom2 = new DOMDocument();
        $dom2->loadXML($xml2);

        $status2 = OneLogin_Saml2_Utils::getStatus($dom2);
        $this->assertEquals(OneLogin_Saml2_Constants::STATUS_RESPONDER, $status2['code']);
        $this->assertEmpty($status2['msg']);

        $xml3 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64'));
        $dom3 = new DOMDocument();
        $dom3->loadXML($xml3);

        $status3 = OneLogin_Saml2_Utils::getStatus($dom3);
        $this->assertEquals(OneLogin_Saml2_Constants::STATUS_RESPONDER, $status3['code']);
        $this->assertEquals('something_is_wrong', $status3['msg']);

        $xmlInv = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status.xml.base64'));
        $domInv = new DOMDocument();
        $domInv->loadXML($xmlInv);

        try {
            $statusInv = OneLogin_Saml2_Utils::getStatus($domInv);
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertEquals('Missing Status on response', $e->getMessage());
        }

        $xmlInv2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status_code.xml.base64'));
        $domInv2 = new DOMDocument();
        $domInv2->loadXML($xmlInv2);

        try {
            $statusInv2 = OneLogin_Saml2_Utils::getStatus($domInv2);
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertEquals('Missing Status Code on response', $e->getMessage());
        }
    }

    /**
    * Tests the parseDuration method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::parseDuration
    */
    public function testParseDuration()
    {
        $duration = 'PT1393462294S';
        $timestamp = 1393876825;

        $parsedDuration = OneLogin_Saml2_Utils::parseDuration($duration, $timestamp);
        $this->assertEquals(2787339119, $parsedDuration);

        $parsedDuration2 = OneLogin_Saml2_Utils::parseDuration($duration);

        $this->assertTrue($parsedDuration2 > $parsedDuration);

        $invalidDuration = 'PT1Y';
        try {
            $parsedDuration3 = OneLogin_Saml2_Utils::parseDuration($invalidDuration);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid ISO 8601 duration', $e->getMessage());
        }

        $newDuration = 'P1Y1M';
        $parsedDuration4 = OneLogin_Saml2_Utils::parseDuration($newDuration, $timestamp);
        $this->assertEquals(1428091225, $parsedDuration4);

        $negDuration = '-P14M';
        $parsedDuration5 = OneLogin_Saml2_Utils::parseDuration($negDuration, $timestamp);
        $this->assertEquals(1357243225, $parsedDuration5);
    }

    /**
    * Tests the parseSAML2Time method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::parseSAML2Time
    */
    public function testParseSAML2Time()
    {
        $time = 1386650371;
        $SAMLTime = '2013-12-10T04:39:31Z';
        $this->assertEquals($time, OneLogin_Saml2_Utils::parseSAML2Time($SAMLTime));

        try {
            OneLogin_Saml2_Utils::parseSAML2Time('invalidSAMLTime');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid SAML2 timestamp passed', $e->getMessage());
        }

        // Now test if toolkit supports milliseconds
        $SAMLTime2 = '2013-12-10T04:39:31.120Z';
        $this->assertEquals($time, OneLogin_Saml2_Utils::parseSAML2Time($SAMLTime2));
    }

    /**
    * Tests the parseTime2SAML method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::parseTime2SAML
    */
    public function testParseTime2SAML()
    {
        $time = 1386650371;
        $SAMLTime = '2013-12-10T04:39:31Z';
        $this->assertEquals($SAMLTime, OneLogin_Saml2_Utils::parseTime2SAML($time));

        try {
            OneLogin_Saml2_Utils::parseTime2SAML('invalidtime');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Failed to parse time string', $e->getMessage());
        }
    }

    /**
    * Tests the getExpireTime method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::getExpireTime
    */
    public function testGetExpireTime()
    {
        $this->assertNull(OneLogin_Saml2_Utils::getExpireTime());

        $this->assertNotNull(OneLogin_Saml2_Utils::getExpireTime('PT1393462294S'));

        $this->assertEquals('1418186371', OneLogin_Saml2_Utils::getExpireTime('PT1393462294S', '2014-12-10T04:39:31Z'));
        $this->assertEquals('1418186371', OneLogin_Saml2_Utils::getExpireTime('PT1393462294S', 1418186371));

        $this->assertNotEquals('1418186371', OneLogin_Saml2_Utils::getExpireTime('PT1393462294S', '2012-12-10T04:39:31Z'));
    }

    /**
    * Tests the query method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::query
    */
    public function testQuery()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64'));
        $dom = new DOMDocument();
        $dom->loadXML($xml);

        $assertionNodes = OneLogin_Saml2_Utils::query($dom, '/samlp:Response/saml:Assertion');
        $this->assertEquals(1, $assertionNodes->length);
        $assertion = $assertionNodes->item(0);
        $this->assertEquals('saml:Assertion', $assertion->tagName);

        $attributeStatementNodes = OneLogin_Saml2_Utils::query($dom, '/samlp:Response/saml:Assertion/saml:AttributeStatement');
        $this->assertEquals(1, $attributeStatementNodes->length);
        $attributeStatement = $attributeStatementNodes->item(0);
        $this->assertEquals('saml:AttributeStatement', $attributeStatement->tagName);

        $attributeStatementNodes2 = OneLogin_Saml2_Utils::query($dom, './saml:AttributeStatement', $assertion);
        $this->assertEquals(1, $attributeStatementNodes2->length);
        $attributeStatement2 = $attributeStatementNodes2->item(0);
        $this->assertEquals($attributeStatement, $attributeStatement2);

        $signatureResNodes = OneLogin_Saml2_Utils::query($dom, '/samlp:Response/ds:Signature');
        $this->assertEquals(1, $signatureResNodes->length);
        $signatureRes = $signatureResNodes->item(0);
        $this->assertEquals('ds:Signature', $signatureRes->tagName);

        $signatureNodes = OneLogin_Saml2_Utils::query($dom, '/samlp:Response/saml:Assertion/ds:Signature');
        $this->assertEquals(1, $signatureNodes->length);
        $signature = $signatureNodes->item(0);
        $this->assertEquals('ds:Signature', $signature->tagName);

        $signatureNodes2 = OneLogin_Saml2_Utils::query($dom, './ds:Signature', $assertion);
        $this->assertEquals(1, $signatureNodes2->length);
        $signature2 = $signatureNodes2->item(0);
        $this->assertEquals($signature->textContent, $signature2->textContent);
        $this->assertNotEquals($signatureRes->textContent, $signature2->textContent);

        $signatureNodes3 = OneLogin_Saml2_Utils::query($dom, './ds:SignatureValue', $assertion);
        $this->assertEquals(0, $signatureNodes3->length);

        $signatureNodes4 = OneLogin_Saml2_Utils::query($dom, './ds:Signature/ds:SignatureValue', $assertion);
        $this->assertEquals(1, $signatureNodes4->length);

        $signatureNodes5 = OneLogin_Saml2_Utils::query($dom, './/ds:SignatureValue', $assertion);
        $this->assertEquals(1, $signatureNodes5->length);
    }

    /**
    * Tests the generateNameId method of the OneLogin_Saml2_Utils
    * Adding a SPNameQualifier
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    */
    public function testGenerateNameIdWithSPNameQualifier()
    {
        //$xml = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.$decrypted.'</root>';
        //$newDoc = new DOMDocument();

        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';
        $nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

        $nameId = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat
        );

        $expectedNameId = '<saml:NameID SPNameQualifier="http://stuff.com/endpoints/metadata.php" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';

        $this->assertEquals($nameId, $expectedNameId);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $x509cert = $settingsInfo['idp']['x509cert'];
        $key = OneLogin_Saml2_Utils::formatCert($x509cert);

        $nameIdEnc = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat,
            $key
        );

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>';
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);
    }

    /**
    * Tests the generateNameId method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    */
    public function testGenerateNameIdWithoutFormat()
    {
        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';

        $nameId = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            null,
            null
        );

        $expectedNameId = '<saml:NameID>ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';
        $this->assertEquals($nameId, $expectedNameId);
    }

    /**
    * Tests the generateNameId method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    */
    public function testGenerateNameIdWithoutSPNameQualifier()
    {
        //$xml = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.$decrypted.'</root>';
        //$newDoc = new DOMDocument();

        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';
        $nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

        $nameId = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            null,
            $nameIDFormat
        );

        $expectedNameId = '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';

        $this->assertEquals($nameId, $expectedNameId);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $x509cert = $settingsInfo['idp']['x509cert'];
        $key = OneLogin_Saml2_Utils::formatCert($x509cert);

        $nameIdEnc = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            null,
            $nameIDFormat,
            $key
        );

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>';
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);
    }

    /**
    * Tests the generateNameId method of the OneLogin_Saml2_Utils
    * Adding a NameQualifier
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    */
    public function testGenerateNameIdWithNameQualifier()
    {
        //$xml = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.$decrypted.'</root>';
        //$newDoc = new DOMDocument();

        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';
        $nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $nameQualifier = 'http://stuff.com/endpoints/acs.php';

        $nameId = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat,
            null,
            $nameQualifier
        );

        $expectedNameId = '<saml:NameID SPNameQualifier="http://stuff.com/endpoints/metadata.php" NameQualifier="http://stuff.com/endpoints/acs.php" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';

        $this->assertEquals($nameId, $expectedNameId);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $x509cert = $settingsInfo['idp']['x509cert'];
        $key = OneLogin_Saml2_Utils::formatCert($x509cert);

        $nameIdEnc = OneLogin_Saml2_Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat,
            $key,
            $nameQualifier
        );

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>';
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);
    }

    /**
    * Tests the deleteLocalSession method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::deleteLocalSession
    */
    public function testDeleteLocalSession()
    {
        if (getenv("TRAVIS")) {
            // Can't test that on TRAVIS
            $this->markTestSkipped("Can't test that on TRAVIS");
        } else {
            if (!isset($_SESSION)) {
                $_SESSION = array();
            }
            $_SESSION['samltest'] = true;

            $this->assertTrue(isset($_SESSION['samltest']));
            $this->assertTrue($_SESSION['samltest']);

            OneLogin_Saml2_Utils::deleteLocalSession();
            $this->assertEmpty($_SESSION);
            $this->assertFalse(isset($_SESSION['samltest']));

            $prev = error_reporting(0);
            session_start();
            error_reporting($prev);

            $_SESSION['samltest'] = true;
            OneLogin_Saml2_Utils::deleteLocalSession();
            $this->assertEmpty($_SESSION);
            $this->assertFalse(isset($_SESSION['samltest']));
        }
    }

    /**
    * Tests the isSessionStarted method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::isSessionStarted
    */
    public function testisSessionStarted()
    {
        if (getenv("TRAVIS") || (PHP_MAJOR_VERSION == 7 && PHP_MINOR_VERSION == 1)) {
            // Can't test that on TRAVIS
            $this->markTestSkipped("Can't test that on TRAVIS");
        } else {
            $this->assertFalse(OneLogin_Saml2_Utils::isSessionStarted());

            $prev = error_reporting(0);
            session_start();
            error_reporting($prev);

            $this->assertTrue(OneLogin_Saml2_Utils::isSessionStarted());
        }
    }


    /**
    * Tests the calculateX509Fingerprint method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::calculateX509Fingerprint
    */
    public function testCalculateX509Fingerprint()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $certPath = $settings->getCertPath();

        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $this->assertNull(OneLogin_Saml2_Utils::calculateX509Fingerprint($key));

        $this->assertNull(OneLogin_Saml2_Utils::calculateX509Fingerprint(""));

        $this->assertNull(OneLogin_Saml2_Utils::calculateX509Fingerprint($settingsInfo['idp']['x509cert']));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils::calculateX509Fingerprint(OneLogin_Saml2_Utils::formatCert($settingsInfo['idp']['x509cert'])));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils::calculateX509Fingerprint($cert));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha1'));

        $this->assertEquals('c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba', OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha256'));

        $this->assertEquals('bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d', OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha384'));

        $this->assertEquals('3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff', OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha512'));
    }

    /**
    * Tests the formatFingerPrint method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::formatFingerPrint
    */
    public function testFormatFingerPrint()
    {
        $fingerPrint1 = 'AF:E7:1C:28:EF:74:0B:C8:74:25:BE:13:A2:26:3D:37:97:1D:A1:F9';
        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils::formatFingerPrint($fingerPrint1));

        $fingerPrint2 = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', OneLogin_Saml2_Utils::formatFingerPrint($fingerPrint2));
    }

    /**
    * Tests the decryptElement method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::decryptElement
    */
    public function testDecryptElement()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $key = $settings->getSPkey();
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
        $seckey->loadKey($key);

        $xmlNameIdEnc = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64'));
        $domNameIdEnc = new DOMDocument();
        $domNameIdEnc->loadXML($xmlNameIdEnc);
        $encryptedNameIDNodes = $domNameIdEnc->getElementsByTagName('EncryptedID');
        $encryptedData = $encryptedNameIDNodes->item(0)->firstChild;
        $decryptedNameId = OneLogin_Saml2_Utils::decryptElement($encryptedData, $seckey);
        $this->assertEquals('saml:NameID', $decryptedNameId->tagName);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId->nodeValue);

        $xmlAsssertionEnc = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64'));
        $domAsssertionEnc = new DOMDocument();
        $domAsssertionEnc->loadXML($xmlAsssertionEnc);
        $encryptedAssertionEncNodes = $domAsssertionEnc->getElementsByTagName('EncryptedAssertion');
        $encryptedAssertionEncNode = $encryptedAssertionEncNodes->item(0);
        $encryptedDataAssertNodes = $encryptedAssertionEncNode->getElementsByTagName('EncryptedData');
        $encryptedDataAssert = $encryptedDataAssertNodes->item(0);
        $decryptedAssertion = OneLogin_Saml2_Utils::decryptElement($encryptedDataAssert, $seckey);

        $this->assertEquals('saml:Assertion', $decryptedAssertion->tagName);

        try {
            $res = OneLogin_Saml2_Utils::decryptElement($encryptedNameIDNodes->item(0), $seckey);
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key in message', $e->getMessage());
        }

        $key2 = file_get_contents(TEST_ROOT . '/data/misc/sp2.key');
        $seckey2 = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
        $seckey2->loadKey($key2);
        $decryptedNameId2 = OneLogin_Saml2_Utils::decryptElement($encryptedData, $seckey2);
        $this->assertEquals('saml:NameID', $decryptedNameId2->tagName);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId2->nodeValue);

        $key3 = file_get_contents(TEST_ROOT . '/data/misc/sp2.key');
        $seckey3 = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, array('type'=>'private'));
        $seckey3->loadKey($key3);
        try {
            $res = OneLogin_Saml2_Utils::decryptElement($encryptedData, $seckey3);
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key used to encrypt  the symmetric key for the message', $e->getMessage());
        }

        $xmlNameIdEnc2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_EncMethod.xml.base64'));
        $domNameIdEnc2 = new DOMDocument();
        $domNameIdEnc2->loadXML($xmlNameIdEnc2);
        $encryptedNameIDNodes2 = $domNameIdEnc2->getElementsByTagName('EncryptedID');
        $encryptedData2 = $encryptedNameIDNodes2->item(0)->firstChild;
        try {
            $res = OneLogin_Saml2_Utils::decryptElement($encryptedData2, $seckey);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Unsupported or not allowed key transport algorithm', $e->getMessage());
        }

        $xmlNameIdEnc3 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_keyinfo.xml.base64'));
        $domNameIdEnc3 = new DOMDocument();
        $domNameIdEnc3->loadXML($xmlNameIdEnc3);
        $encryptedNameIDNodes3 = $domNameIdEnc3->getElementsByTagName('EncryptedID');
        $encryptedData3 = $encryptedNameIDNodes3->item(0)->firstChild;
        try {
            $res = OneLogin_Saml2_Utils::decryptElement($encryptedData3, $seckey);
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key in message', $e->getMessage());
        }
    }

    /**
    * An encrypted NameID generated by the toolkit uses rsa-oaep-mgf1p key transport
    * and can be decrypted with the default settings and with rsa-1_5 disabled
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    */
    public function testGenerateNameIdEncryptedRoundTrip()
    {
        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
        $seckey->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));

        $nameIdEnc = OneLogin_Saml2_Utils::generateNameId('ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde', null, null, $cert);
        $this->assertNotContains(XMLSecurityKey::RSA_1_5, $nameIdEnc);
        $this->assertContains(XMLSecurityKey::RSA_OAEP_MGF1P, $nameIdEnc);

        foreach (array(true, false) as $allowRSA15KeyTransport) {
            $dom = new DOMDocument();
            $dom->loadXML('<root xmlns:saml="' . OneLogin_Saml2_Constants::NS_SAML . '">' . $nameIdEnc . '</root>');
            $decrypted = OneLogin_Saml2_Utils::decryptElement($dom->getElementsByTagName('EncryptedData')->item(0), $seckey, true, $allowRSA15KeyTransport);
            $this->assertEquals('ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde', $decrypted->nodeValue);
        }
    }

    /**
    * The bundled xmlseclibs encrypts and decrypts with mcrypt, deprecated as of PHP 7.1.
    * Its E_DEPRECATED notices must not be raised (error handlers that convert them to
    * exceptions, like the PHPUnit one, made every encryption and decryption fail) and the
    * error_reporting level must be restored, also when the mcrypt operation fails.
    *
    * @covers OneLogin_Saml2_Utils::generateNameId
    * @covers OneLogin_Saml2_Utils::decryptElement
    */
    public function testMcryptDeprecationsAreNotRaised()
    {
        $prev = error_reporting(E_ALL);
        try {
            $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');
            $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
            $seckey->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));

            $nameIdEnc = OneLogin_Saml2_Utils::generateNameId('ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde', null, null, $cert);
            $this->assertEquals(E_ALL, error_reporting());

            $dom = new DOMDocument();
            $dom->loadXML('<root xmlns:saml="' . OneLogin_Saml2_Constants::NS_SAML . '">' . $nameIdEnc . '</root>');
            $decrypted = OneLogin_Saml2_Utils::decryptElement($dom->getElementsByTagName('EncryptedData')->item(0), $seckey);
            $this->assertEquals('ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde', $decrypted->nodeValue);
            $this->assertEquals(E_ALL, error_reporting());

            // A key larger than the cipher supports makes mcrypt_generic_init raise a warning
            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_CBC);
            $symmetricKey->loadKey(str_repeat('k', 40));
            try {
                $symmetricKey->encryptData('data');
                $this->fail('Exception was not raised');
            } catch (PHPUnit_Framework_Error_Warning $e) {
                $this->assertContains('mcrypt_generic_init', $e->getMessage());
            }
            $this->assertEquals(E_ALL, error_reporting());
        } catch (Exception $e) {
            error_reporting($prev);
            throw $e;
        }
        error_reporting($prev);
    }

    /**
    * @covers OneLogin_Saml2_Utils::castKey
    */
    public function testCastKey()
    {
        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
        $key->loadKey($cert, false, true);

        $this->assertSame($key, OneLogin_Saml2_Utils::castKey($key, XMLSecurityKey::RSA_SHA1));

        $newKey = OneLogin_Saml2_Utils::castKey($key, XMLSecurityKey::RSA_SHA256);
        $this->assertEquals(XMLSecurityKey::RSA_SHA256, $newKey->type);
        $this->assertNotNull($newKey->getX509Certificate());
        $this->assertEquals($key->getX509Certificate(), $newKey->getX509Certificate());

        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        $privateKey->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));
        $this->assertEquals(1, $newKey->verifySignature('data', $privateKey->signData('data')));

        // A key loaded without certificate is still cast
        $keyDetails = openssl_pkey_get_details($key->key);
        $publicKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
        $publicKey->loadKey($keyDetails['key']);
        $newPublicKey = OneLogin_Saml2_Utils::castKey($publicKey, XMLSecurityKey::RSA_SHA256);
        $this->assertNull($newPublicKey->getX509Certificate());
        $this->assertEquals(1, $newPublicKey->verifySignature('data', $privateKey->signData('data')));

        try {
            OneLogin_Saml2_Utils::castKey($key, XMLSecurityKey::HMAC_SHA1);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertEquals('Unsupported signing algorithm.', $e->getMessage());
        }
    }

    /**
    * HTTP-Redirect signatures are validated with every supported SigAlg, with one
    * or several IdP signing certificates
    *
    * @covers OneLogin_Saml2_Utils::validateBinarySign
    */
    public function testValidateBinarySignAlgorithms()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');
        $idpData = array('x509cert' => $cert);
        // First cert does not match the signing key
        $idpDataMulti = array('x509certMulti' => array('signing' => array(
            OneLogin_Saml2_Utils::formatCert($settingsInfo['idp']['x509cert']),
            $cert
        )));

        $samlRequest = base64_encode(gzdeflate('<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e" Version="2.0" IssueInstant="2014-03-31T18:23:24Z"/>'));
        $relayState = 'http://relay.example.com/';

        foreach (array(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA384, XMLSecurityKey::RSA_SHA512) as $signAlg) {
            $key = new XMLSecurityKey($signAlg, array('type' => 'private'));
            $key->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));
            $msg = 'SAMLRequest='.urlencode($samlRequest).'&RelayState='.urlencode($relayState).'&SigAlg='.urlencode($signAlg);
            $getData = array(
                'SAMLRequest' => $samlRequest,
                'RelayState' => $relayState,
                'SigAlg' => $signAlg,
                'Signature' => base64_encode($key->signData($msg))
            );

            $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign('SAMLRequest', $getData, $idpData), $signAlg);
            $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign('SAMLRequest', $getData, $idpDataMulti), $signAlg);

            $getData['RelayState'] = 'http://evil.example.com/';
            $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign('SAMLRequest', $getData, $idpData), $signAlg);
            $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign('SAMLRequest', $getData, $idpDataMulti), $signAlg);
        }
    }

    /**
    * Tests the addSign method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::addSign
    */
    public function testAddSign()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $key = $settings->getSPkey();
        $cert = $settings->getSPcert();

        $xmlAuthn = base64_decode(file_get_contents(TEST_ROOT . '/data/requests/authn_request.xml.base64'));
        $xmlAuthnSigned = OneLogin_Saml2_Utils::addSign($xmlAuthn, $key, $cert);
        $this->assertContains('<ds:SignatureValue>', $xmlAuthnSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', $xmlAuthnSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>', $xmlAuthnSigned);
        $res = new DOMDocument();
        $res->loadXML($xmlAuthnSigned);
        $dsSignature = $res->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature->tagName);

        $dom = new DOMDocument();
        $dom->loadXML($xmlAuthn);
        $xmlAuthnSigned2 = OneLogin_Saml2_Utils::addSign($dom, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlAuthnSigned2);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlAuthnSigned2);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlAuthnSigned2);
        $res2 = new DOMDocument();
        $res2->loadXML($xmlAuthnSigned2);
        $dsSignature2 = $res2->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature2->tagName);

        $xmlLogoutReq = base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml.base64'));
        $xmlLogoutReqSigned = OneLogin_Saml2_Utils::addSign($xmlLogoutReq, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlLogoutReqSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutReqSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutReqSigned);
        $res3 = new DOMDocument();
        $res3->loadXML($xmlLogoutReqSigned);
        $dsSignature3 = $res3->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature3->tagName);

        $xmlLogoutRes = base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64'));
        $xmlLogoutResSigned = OneLogin_Saml2_Utils::addSign($xmlLogoutRes, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlLogoutResSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutResSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutResSigned);
        $res4 = new DOMDocument();
        $res4->loadXML($xmlLogoutResSigned);
        $dsSignature4 = $res4->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature4->tagName);

        $xmlMetadata = file_get_contents(TEST_ROOT . '/data/metadata/metadata_settings1.xml');
        $xmlMetadataSigned = OneLogin_Saml2_Utils::addSign($xmlMetadata, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlMetadataSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlMetadataSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlMetadataSigned);
        $res5 = new DOMDocument();
        $res5->loadXML($xmlMetadataSigned);
        $dsSignature5 = $res5->firstChild->firstChild;
        $this->assertContains('ds:Signature', $dsSignature5->tagName);
    }

    /**
    * Tests the validateSign method of the OneLogin_Saml2_Utils
    *
    * @covers OneLogin_Saml2_Utils::validateSign
    */
    public function testValidateSign()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();
        $cert = $idpData['x509cert'];
        $fingerprint = OneLogin_Saml2_Utils::calculateX509Fingerprint($cert);
        $fingerprint256 = OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha256');

        $xmlMetadataSigned = file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml');
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, $cert));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, null, $fingerprint));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha1'));
        $this->assertFalse(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha256'));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, null, $fingerprint256, 'sha256'));

        $xmlResponseMsgSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64'));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseMsgSigned, $cert));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseMsgSigned, null, $fingerprint));

        $xmlResponseAssertSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64'));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseAssertSigned, $cert));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseAssertSigned, null, $fingerprint));

        $xmlResponseDoubleSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64'));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseDoubleSigned, $cert));
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($xmlResponseDoubleSigned, null, $fingerprint));

        $dom = new DOMDocument();
        $dom->loadXML($xmlResponseMsgSigned);
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($dom, $cert));

        $dom->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        try {
            $this->assertFalse(OneLogin_Saml2_Utils::validateSign($dom, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference validation failed', $e->getMessage());
        }

        $dom2 = new DOMDocument();
        $dom2->loadXML($xmlResponseMsgSigned);
        $assertElem = $dom2->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($assertElem, $cert));

        $dom3 = new DOMDocument();
        $dom3->loadXML($xmlResponseMsgSigned);
        $dom3->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $assertElem2 = $dom3->firstChild->firstChild->nextSibling->nextSibling;
        try {
            $this->assertTrue(OneLogin_Saml2_Utils::validateSign($assertElem2, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference validation failed', $e->getMessage());
        }

        $invalidFingerprint = 'afe71c34ef740bc87434be13a2263d31271da1f9';
        $this->assertFalse(OneLogin_Saml2_Utils::validateSign($xmlMetadataSigned, null, $invalidFingerprint));

        $noSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_signature.xml.base64'));
        try {
            $this->assertFalse(OneLogin_Saml2_Utils::validateSign($noSigned, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Cannot locate Signature Node', $e->getMessage());
        }

        $noKey = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64'));
        try {
            $this->assertFalse(OneLogin_Saml2_Utils::validateSign($noKey, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('We have no idea about the key', $e->getMessage());
        }

        $signatureWrapping = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/signature_wrapping_attack.xml.base64'));
        try {
            $this->assertFalse(OneLogin_Saml2_Utils::validateSign($signatureWrapping, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference URI must identify exactly one element', $e->getMessage());
        }
    }

    /**
     * Runs the callable failing on any PHP error that the code of the toolkit raises, deprecations
     * included. Without it the failure of the code that is checked here depends on the assertions
     * (calculateX509Fingerprint asserts that it gets a string: a failed assertion is a warning when
     * the assertions are enabled, but with the assertions disabled, as in production, the same code
     * raises nothing). The errors of the libraries are not the ones that are checked (xmlseclibs
     * emits a warning when the certificate of a KeyInfo can not be read).
     *
     * @param callable $callable
     *
     * @return mixed The value returned by the callable
     */
    private function withPhpErrorsAsExceptions(callable $callable)
    {
        $libDir = dirname(TEST_ROOT) . '/lib/';
        $toException = function ($severity, $message, $file, $line) use ($libDir) {
            if (strpos($file, $libDir) !== 0) {
                return true;
            }
            throw new ErrorException($message, 0, $severity, $file, $line);
        };
        set_error_handler($toException);
        try {
            return $callable();
        } finally {
            restore_error_handler();
        }
    }

    /**
     * @param string      $xml     Signed XML
     * @param string|null $keyInfo KeyInfo (as XML) that replaces the one of the first Signature of the document, null to remove it
     *                             (the KeyInfo of a Signature inside the signed content is signed by the other Signature, so it is not touched)
     *
     * @return string The XML (as a received message, so it is parsed again by validateSign)
     */
    private function replaceKeyInfo($xml, $keyInfo = null)
    {
        $dom = new DOMDocument();
        $dom->loadXML($xml);

        $signature = $dom->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Signature')->item(0);
        $keyInfos = $signature->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'KeyInfo');
        for ($i = $keyInfos->length - 1; $i >= 0; $i--) {
            $oldKeyInfo = $keyInfos->item($i);
            if ($keyInfo !== null) {
                $fragment = $dom->createDocumentFragment();
                $this->assertTrue($fragment->appendXML(preg_replace('/^<ds:KeyInfo/', '<ds:KeyInfo xmlns:ds="' . XMLSecurityDSig::XMLDSIGNS . '"', $keyInfo)));
                $oldKeyInfo->parentNode->replaceChild($fragment, $oldKeyInfo);
            } else {
                $oldKeyInfo->parentNode->removeChild($oldKeyInfo);
            }
        }

        return $dom->saveXML();
    }

    /**
     * KeyInfo is not covered by the signature, so a message can be received without it. With the
     * certificate of the IdP configured the signature is validated, and if only the fingerprint
     * is configured there is no certificate to compare it with, so the signature is not valid
     * (and no PHP error is raised)
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateSignWithoutKeyInfo()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();
        $cert = $idpData['x509cert'];
        $fingerprint = OneLogin_Saml2_Utils::calculateX509Fingerprint($cert);
        $fingerprint256 = OneLogin_Saml2_Utils::calculateX509Fingerprint($cert, 'sha256');

        $signedXmls = array(
            'metadata' => file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml'),
            'message' => base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64')),
            'assertion' => base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64')),
            'double signed' => base64_decode(file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64')),
        );
        foreach ($signedXmls as $name => $xml) {
            // Control: the KeyInfo that this test writes is a valid one
            $withKeyInfo = $this->replaceKeyInfo($xml, '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' . $settingsInfo['idp']['x509cert'] . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>');
            $this->assertTrue(OneLogin_Saml2_Utils::validateSign($withKeyInfo, null, $fingerprint), "$name, with KeyInfo");

            $noKeyInfo = $this->replaceKeyInfo($xml);
            // The metadata and the double signed response have other KeyInfo (the ones that are signed), the Signature that is validated has none
            $dom = new DOMDocument();
            $dom->loadXML($noKeyInfo);
            $signature = $dom->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'Signature')->item(0);
            $this->assertEquals(0, $signature->getElementsByTagNameNS(XMLSecurityDSig::XMLDSIGNS, 'KeyInfo')->length, $name);

            $this->assertTrue(OneLogin_Saml2_Utils::validateSign($noKeyInfo, $cert), "$name, certificate");
            $this->assertTrue(OneLogin_Saml2_Utils::validateSign($noKeyInfo, null, null, 'sha1', null, array($cert)), "$name, certificates");
            $validateWithFingerprint = function () use ($noKeyInfo, $fingerprint) {
                return OneLogin_Saml2_Utils::validateSign($noKeyInfo, null, $fingerprint);
            };
            $this->assertFalse($this->withPhpErrorsAsExceptions($validateWithFingerprint), "$name, fingerprint");
            $validateWithFingerprint256 = function () use ($noKeyInfo, $fingerprint256) {
                return OneLogin_Saml2_Utils::validateSign($noKeyInfo, null, $fingerprint256, 'sha256');
            };
            $this->assertFalse($this->withPhpErrorsAsExceptions($validateWithFingerprint256), "$name, sha256 fingerprint");
        }
    }

    /**
     * The KeyInfo can be changed by anybody (it is not signed), so whatever it contains the
     * validation by fingerprint fails as an Exception or returns false, and only the
     * certificate that matches the fingerprint can be used to verify the signature
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateSignWithUnusableKeyInfo()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();
        $fingerprint = OneLogin_Saml2_Utils::calculateX509Fingerprint($idpData['x509cert']);
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64'));

        $keyInfos = array(
            'empty' => '<ds:KeyInfo/>',
            'empty X509Data' => '<ds:KeyInfo><ds:X509Data/></ds:KeyInfo>',
            'empty X509Certificate' => '<ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo>',
            'blank X509Certificate' => '<ds:KeyInfo><ds:X509Data><ds:X509Certificate> </ds:X509Certificate></ds:X509Data></ds:KeyInfo>',
            'not base64 X509Certificate' => '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>not a certificate!</ds:X509Certificate></ds:X509Data></ds:KeyInfo>',
            'not a certificate X509Certificate' => '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>' . base64_encode('not a certificate') . '</ds:X509Certificate></ds:X509Data></ds:KeyInfo>',
            'X509SubjectName only' => '<ds:KeyInfo><ds:X509Data><ds:X509SubjectName>CN=feide.erlang.no</ds:X509SubjectName></ds:X509Data></ds:KeyInfo>',
            'KeyName only' => '<ds:KeyInfo><ds:KeyName>key</ds:KeyName></ds:KeyInfo>',
            'KeyValue only' => '<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AQAB</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>',
        );
        foreach ($keyInfos as $name => $keyInfo) {
            $modifiedXml = $this->replaceKeyInfo($xml, $keyInfo);

            // A PHP error of the toolkit fails the test (an Error, on PHP 7, is not caught here and fails it too)
            $validate = function () use ($modifiedXml, $fingerprint) {
                return OneLogin_Saml2_Utils::validateSign($modifiedXml, null, $fingerprint);
            };
            try {
                $result = $this->withPhpErrorsAsExceptions($validate);
            } catch (ErrorException $e) {
                throw $e;
            } catch (Exception $e) {
                $result = false;
            }
            $this->assertFalse($result, $name);
        }
    }

    /**
     * Tests the validateBinarySign method of the Utils
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignIsValid()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLRequest';
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLRequest=' . urlencode('fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE='). '&RelayState='.urlencode('_1037fbc88ec82ce8e770b2bed1119747bb812a07e6') . '&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature=' . urlencode('L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrc');
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        unset($_SERVER['QUERY_STRING']);
        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLResponse';
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLResponse='.urlencode('fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A').'&RelayState='.urlencode('https://pitbulk.no-ip.org/newonelogin/demo1/index.php').'&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature='.urlencode('vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=');
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));
    }

    /**
     * Tests the validateBinarySign method of the Utils
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignIsValidx509certMulti()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLRequest';
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLRequest=' . urlencode('fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE='). '&RelayState='.urlencode('_1037fbc88ec82ce8e770b2bed1119747bb812a07e6') . '&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature=' . urlencode('L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrc');
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        unset($_SERVER['QUERY_STRING']);
        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLResponse';
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLResponse='.urlencode('fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A').'&RelayState='.urlencode('https://pitbulk.no-ip.org/newonelogin/demo1/index.php').'&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature='.urlencode('vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=');
        $this->assertTrue(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case where the signature is wrong 
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignSignatureWrong()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'WRONGL2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLRequest';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'WRONGvfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        $retrieveParametersFromServer = false;
        $messageType = 'SAMLResponse';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case where the cert is wrong 
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignCertWrong()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settingsInfo['idp']['x509cert'] = 'MIICZDCCAc2gAwIBAgIBADANBgkqhkiG9w0BAQ0FADBPMQswCQYDVQQGEwJ1czEUMBIGA1UECAwLZXhhbXBsZS5jb20xFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0yNTA1MjQyMjUyNTlaFw0zNTA1MjIyMjUyNTlaME8xCzAJBgNVBAYTAnVzMRQwEgYDVQQIDAtleGFtcGxlLmNvbTEUMBIGA1UECgwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQD4pXDtSHXYCBA7j5Rc5v+Eh1QigIN2BPXcLtzvaQL5ajifXoQsXuSkcO3Rg7kcTVFcSjhtvM7/NUDq8yEq5g6cYCbdJHXCPH2xkotS57YWkY8zYohOuSa8LNLNeBVTcngQqLbprjgUAXjyXq8rlXu80lNgMw8eo7MbQCQpgC4VqwIDAQABo1AwTjAdBgNVHQ4EFgQUmPov0WxzvYUtCluz0AEFFWIx/NYwHwYDVR0jBBgwFoAUmPov0WxzvYUtCluz0AEFFWIx/NYwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQCHTsdA7LbSeDRiqqOHw+50ncIFCC2s4m6qBaxNrwSSyhoZKWhyUNxfnKIB4s/jaQxITn6U8hvuEv6e3Ews+07j4yIISF2SWefStAf8P/7Rt+qHQiV2zcE/RzxW4Trvav1dIfjqF26hOPQqGVnAKGP8wcjsEhwxUVOLP6EUTIoH3A==';
        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        $retrieveParametersFromServer = false;

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        $messageType = 'SAMLRequest';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        $messageType = 'SAMLResponse';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case removed element, ex RelayState
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignRemovedParam()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        $retrieveParametersFromServer = false;

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        unset($getData['RelayState']);
        $messageType = 'SAMLRequest';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer));

        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        unset($getData2['RelayState']);
        $messageType = 'SAMLResponse';
        $this->assertFalse(OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer));
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case No Query String
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignNoQueryString()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        $retrieveParametersFromServer = true;

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        unset($getData['RelayState']);
        $messageType = 'SAMLRequest';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "No query string provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        unset($getData2['RelayState']);
        $messageType = 'SAMLResponse';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "No query string provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case No Cert
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignNoCert()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        unset($idpData['x509cert']);

        $retrieveParametersFromServer = false;

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );
        $messageType = 'SAMLRequest';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "In order to validate the sign on the Logout Request, the x509cert of the IdP is required";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $getData2 = array(
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );
        $messageType = 'SAMLResponse';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "In order to validate the sign on the Logout Response, the x509cert of the IdP is required";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case Invalid Parameters: Ex. SAMLRequest and SAMLResponse present at the same time
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignReqAndRes()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $idpData = $settings->getIdPData();
        $retrieveParametersFromServer = false;

        unset($_SERVER['QUERY_STRING']);
        $getData = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => '_1037fbc88ec82ce8e770b2bed1119747bb812a07e6',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrcTsSFlYYbcqr/g5Kdcgg='
        );

        $messageType = 'SAMLRequest';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Both SAMLRequest and SAMLResponse provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLRequest=' . urlencode('fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE='). '&RelayState='.urlencode('_1037fbc88ec82ce8e770b2bed1119747bb812a07e6') . '%SAMLResponse=' . urlencode('fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A') . '&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature=' . urlencode('L2YrP7Ngms1ew8va4drALt9bjK4ZInIS8V6W3HUSlvW/Hw2VD93vy1jPdDBsrRt8cLIuAkkHatemiq1bbgWyrGqlbX5VA/klRYJvHVowfUh2vuf8s17bdFWUOlsTWXxKaA2lJl93MnzJQsZrfVeCqJrc');
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Both SAMLRequest and SAMLResponse provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $getData2 = array(
            'SAMLRequest' => 'fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=',
            'SAMLResponse' => 'fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A',
            'RelayState' => 'https://pitbulk.no-ip.org/newonelogin/demo1/index.php',
            'SigAlg' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
            'Signature' => 'vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA='
        );

        $messageType = 'SAMLResponse';
        $retrieveParametersFromServer = false;
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Both SAMLRequest and SAMLResponse provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $retrieveParametersFromServer = true;
        $_SERVER['QUERY_STRING'] = 'SAMLRequest='. urlencode('fZJNa+MwEIb/ivHdiTyyZEskhkJYCPQDtmUPvQRZHm8NtqRKMuTnr2J3IbuHXsQwM887My86BDVPTj7a33aJP/FzwRCz6zyZINfKMV+8kVaFMUijZgwyavn68PQoYUek8zZabaf8DvmeUCGgj6M1eXY+HfOLILwHVQ+MK1ozrBG7itQcKzpQ3pQCdDU0DdQIefYLfUjkMU9CCQ9hwbMJUZmYUqSsCkILIG8ll8Alg/c8O6VrRqPiSn3E6OR+H+IyDDtt5z2a3tnRxHAXhSns3IfLs2cbX8yLfxgi+iQvBC2IKKB8g1JWm3x7uN0r10V8+yU/9m6HVzW7Cdchh/1900Y8J1vOp+yH9bOK3/t1y4x9MaytMnplwogm5u1l6KDrgUHFGeVEU92xUlCkrOZMNITr9LIUdvprhW3qtoKTrxhuZp5Nj9f2gn0D0IPQyfnkPlOEQpO0uko1DDSBqqtEl+aITew//m/yn2/U/gE=') . '&SAMLResponse='.urlencode('fZJva8IwEMa/Ssl7TZrW/gnqGHMMwSlM8cXeyLU9NaxNQi9lfvxVZczB5ptwSe733MPdjQma2qmFPdjOvyE5awiDU1MbUpevCetaoyyQJmWgQVK+VOvH14WSQ6Fca70tbc1ukPsEEGHrtTUsmM8mbDfKUhnFci8gliGINI/yXIAAiYnsw6JIRgWWAKlkwRZb6skJ64V6nKjDuSEPxvdPIowHIhpIsQkTFaYqSt9ZMEPy2oC/UEfvHSnOnfZFV38MjR1oN7TtgRv8tAZre9CGV9jYkGtT4Wnoju6Bauprme/ebOyErZbPi9XLfLnDoohwhHGc5WVSVhjCKM6rBMpYQpWJrIizfZ4IZNPxuTPqYrmd/m+EdONqPOfy8yG5rhxv0EMFHs52xvxWaHyd3tqD7+j37clWGGyh7vD+POiSrdZdWSIR49NrhR9R/teGTL8A').'&RelayState='.urlencode('https://pitbulk.no-ip.org/newonelogin/demo1/index.php').'&SigAlg='.urlencode('http://www.w3.org/2000/09/xmldsig#rsa-sha1').'&Signature='.urlencode('vfWbbc47PkP3ejx4bjKsRX7lo9Ml1WRoE5J5owF/0mnyKHfSY6XbhO1wwjBV5vWdrUVX+xp6slHyAf4YoAsXFS0qhan6txDiZY4Oec6yE+l10iZbzvie06I4GPak4QrQ4gAyXOSzwCrRmJu4gnpeUxZ6IqKtdrKfAYRAcVfNKGA=');
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData2, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Both SAMLRequest and SAMLResponse provided";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }
    }

    /**
     * Tests the validateBinarySign method of the Utils
     * Case Invalid Parameters: Ex. Duplicated Parameters
     * 
     * @covers OneLogin_Saml2_Utils::validateSign
     */
    public function testValidateBinarySignDuplicatedParameters()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings6.php';

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $idpData = $settings->getIdPData();

        $getData = array();
        $retrieveParametersFromServer = true;
        $messageType = 'SAMLRequest';

        $_SERVER['QUERY_STRING'] = 'SAMLRequest=xxx&SAMLRequest=yyy';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Duplicate parameter in query string";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $_SERVER['QUERY_STRING'] = 'SAMLResponse=xxx&SAMLResponse=yyy';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Duplicate parameter in query string";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $_SERVER['QUERY_STRING'] = 'RelayState=xxx&RelayState=yyy';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Duplicate parameter in query string";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }

        $_SERVER['QUERY_STRING'] = 'SigAlg=xxx&SigAlg=yyy';
        try {
            OneLogin_Saml2_Utils::validateBinarySign($messageType, $getData, $idpData, $retrieveParametersFromServer);
            $this->fail('Error was not raised');
        } catch (Exception $e) {
            $expectedMessage = "Duplicate parameter in query string";
            $this->assertEquals($expectedMessage, $e->getMessage());
        }
    }
}
