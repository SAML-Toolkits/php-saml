<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\ValidationError;

use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;

use DOMDocument;
use Exception;

/**
 * Unit tests for Utils class
 *
 * @backupStaticAttributes enabled
 */
class UtilsTest extends \PHPUnit\Framework\TestCase
{

    /**
     * Tests the loadXML method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::loadXML
     */
    public function testLoadXML()
    {
        $dom = new DOMDocument();

        $metadataUnloaded = '<xml><EntityDescriptor>';
        $res1 = Utils::loadXML($dom, $metadataUnloaded);
        $this->assertFalse($res1);

        $metadataInvalid = file_get_contents(TEST_ROOT .'/data/metadata/noentity_metadata_settings1.xml');
        $res2 = Utils::loadXML($dom, $metadataInvalid);
        $this->assertTrue($res2 instanceof DOMDocument);

        $metadataOk = file_get_contents(TEST_ROOT .'/data/metadata/metadata_settings1.xml');
        $res3 = Utils::loadXML($dom, $metadataOk);
        $this->assertTrue($res3 instanceof DOMDocument);
    }

    /**
     * Tests the loadXML method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::loadXML
     */
    public function testXMLAttacks()
    {
        $dom = new DOMDocument();

        $attackXXE = '<?xml version="1.0" encoding="ISO-8859-1"?>
                      <!DOCTYPE foo [  
                      <!ELEMENT foo ANY >
                      <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>';
        try {
            $res = Utils::loadXML($dom, $attackXXE);
            $this->fail('Exception was not raised');
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
            $res2 = Utils::loadXML($dom, $xmlWithDTD);
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
            $res3 = Utils::loadXML($dom, $attackXEE);
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
            $res4 = Utils::loadXML($dom, $attackXEEutf16);
            $this->assertFalse($res4);
        } catch (Exception $e) {
            $this->assertEquals('Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks', $e->getMessage());
        }
    }

    /**
     * Tests the validateXML method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::validateXML
     */
    public function testValidateXML()
    {
        $metadataUnloaded = '<xml><EntityDescriptor>';
        $this->assertEquals(Utils::validateXML($metadataUnloaded, 'saml-schema-metadata-2.0.xsd'), 'unloaded_xml');

        $metadataInvalid = file_get_contents(TEST_ROOT .'/data/metadata/noentity_metadata_settings1.xml');
        $this->assertEquals(Utils::validateXML($metadataInvalid, 'saml-schema-metadata-2.0.xsd'), 'invalid_xml');

        $metadataExpired = file_get_contents(TEST_ROOT .'/data/metadata/expired_metadata_settings1.xml');
        $res = Utils::validateXML($metadataExpired, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res instanceof DOMDocument);

        $metadataOk = file_get_contents(TEST_ROOT .'/data/metadata/metadata_settings1.xml');
        $res2 = Utils::validateXML($metadataOk, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res2 instanceof DOMDocument);

        $metadataBadOrder = file_get_contents(TEST_ROOT .'/data/metadata/metadata_bad_order_settings1.xml');
        $res3 = Utils::validateXML($metadataBadOrder, 'saml-schema-metadata-2.0.xsd');
        $this->assertFalse($res3 instanceof DOMDocument);

        $metadataSigned = file_get_contents(TEST_ROOT .'/data/metadata/signed_metadata_settings1.xml');
        $res4 = Utils::validateXML($metadataSigned, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res4 instanceof DOMDocument);

        $dom = new DOMDocument;
        Utils::loadXML($dom, $metadataOk);
        $res5 = Utils::validateXML($dom, 'saml-schema-metadata-2.0.xsd');
        $this->assertTrue($res5 instanceof DOMDocument);
    }

    /**
     * Tests the formatCert method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::formatCert
     */
    public function testFormatCert()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new Settings($settingsInfo);

        $cert = $settingsInfo['idp']['x509cert'];
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertNotContains('-----END CERTIFICATE-----', $cert);
        $this->assertEquals(strlen($cert), 860);

        $formatedCert1 = Utils::formatCert($cert);
        $this->assertContains('-----BEGIN CERTIFICATE-----', $formatedCert1);
        $this->assertContains('-----END CERTIFICATE-----', $formatedCert1);

        $formatedCert2 = Utils::formatCert($cert, true);
        $this->assertEquals($formatedCert1, $formatedCert2);


        $formatedCert3 = Utils::formatCert($cert, false);
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $formatedCert3);
        $this->assertNotContains('-----END CERTIFICATE-----', $formatedCert3);
        $this->assertEquals(strlen($cert), 860);


        $cert2 = $settingsInfo['sp']['x509cert'];
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $cert);
        $this->assertNotContains('-----END CERTIFICATE-----', $cert);
        $this->assertEquals(strlen($cert), 860);

        $formatedCert4 = Utils::formatCert($cert);
        $this->assertContains('-----BEGIN CERTIFICATE-----', $formatedCert4);
        $this->assertContains('-----END CERTIFICATE-----', $formatedCert4);

        $formatedCert5 = Utils::formatCert($cert, true);
        $this->assertEquals($formatedCert4, $formatedCert5);


        $formatedCert6 = Utils::formatCert($cert, false);
        $this->assertNotContains('-----BEGIN CERTIFICATE-----', $formatedCert6);
        $this->assertNotContains('-----END CERTIFICATE-----', $formatedCert6);
        $this->assertEquals(strlen($cert2), 860);

    }

    /**
     * Tests the formatPrivateKey method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::formatPrivateKey
     */
    public function testFormatPrivateKey()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings2.php';

        $settings = new Settings($settingsInfo);

        $key = $settingsInfo['sp']['privateKey'];

        $this->assertNotContains('-----BEGIN RSA PRIVATE KEY-----', $key);
        $this->assertNotContains('-----END RSA PRIVATE KEY-----', $key);
        $this->assertEquals(strlen($key), 816);

        $formatedKey1 = Utils::formatPrivateKey($key);
        $this->assertContains('-----BEGIN RSA PRIVATE KEY-----', $formatedKey1);
        $this->assertContains('-----END RSA PRIVATE KEY-----', $formatedKey1);

        $formatedKey2 = Utils::formatPrivateKey($key, true);
        $this->assertEquals($formatedKey1, $formatedKey2);


        $formatedKey3 = Utils::formatPrivateKey($key, false);

        $this->assertNotContains('-----BEGIN RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertNotContains('-----END RSA PRIVATE KEY-----', $formatedKey3);
        $this->assertEquals(strlen($key), 816);
    }

    /**
     * Tests the redirect method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::redirect
     */
    public function testRedirect()
    {
        // Check relative and absolute
        $hostname = Utils::getSelfHost();
        $url = "http://$hostname/example";
        $url2 = '/example';

        $targetUrl = Utils::redirect($url, array(), true);
        $targetUrl2 = Utils::redirect($url2, array(), true);

        $this->assertEquals($targetUrl, $targetUrl2);

        // Check that accept http/https and reject other protocols
        $url3 = "https://$hostname/example?test=true";
        $url4 = "ftp://$hostname/example";

        $targetUrl3 = Utils::redirect($url3, array(), true);

        try {
            $targetUrl4 = Utils::redirect($url4, array(), true);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Redirect to invalid URL', $e->getMessage());
        }

        // Review parameter prefix
        $parameters1 = array('value1' => 'a');

        $targetUrl5 = Utils::redirect($url, $parameters1, true);
        $this->assertEquals("http://$hostname/example?value1=a", $targetUrl5);

        $targetUrl6 = Utils::redirect($url3, $parameters1, true);
        $this->assertEquals("https://$hostname/example?test=true&value1=a", $targetUrl6);

        // Review parameters
        $parameters2 = array(
            'alphavalue' => 'a',
            'numvalue' => array('1', '2'),
            'testing' => null,
        );

        $targetUrl7 = Utils::redirect($url, $parameters2, true);
        $this->assertEquals("http://$hostname/example?alphavalue=a&numvalue[]=1&numvalue[]=2&testing", $targetUrl7);

        $parameters3 = array(
            'alphavalue' => 'a',
            'emptynumvaluelist' => array(),
            'numvaluelist' => array(''),
        );

        $targetUrl8 = Utils::redirect($url, $parameters3, true);
        $this->assertEquals("http://$hostname/example?alphavalue=a&numvaluelist[]=", $targetUrl8);
    }

    /**
     * @covers OneLogin\Saml2\Utils::setSelfHost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetselfhost()
    {
        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertEquals('example.org', Utils::getSelfHost());

        Utils::setSelfHost('example.com');
        $this->assertEquals('example.com', Utils::getSelfHost());
    }

    /**
     * @covers OneLogin\Saml2\Utils::setProxyVars()
     * @covers OneLogin\Saml2\Utils::getProxyVars()
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testProxyvars()
    {
        $this->assertFalse(Utils::getProxyVars());

        Utils::setProxyVars(true);
        $this->assertTrue(Utils::getProxyVars());

        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
        $_SERVER['SERVER_PORT'] = '80';

        $this->assertTrue(Utils::isHTTPS());

        Utils::setProxyVars(false);
        $this->assertFalse(Utils::isHTTPS());
    }

    /**
     * Tests the getSelfHost method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getSelfHost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfhost()
    {
        if (function_exists('gethostname')) {
            $hostname = gethostname();
        } else {
            $hostname = php_uname("n");
        }

        $this->assertEquals($hostname, Utils::getSelfHost());

        $_SERVER['SERVER_NAME'] = 'example.com';
        $this->assertEquals('example.com', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org';
        $this->assertEquals('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:443';
        $this->assertEquals('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertEquals('example.org', Utils::getSelfHost());

        $_SERVER['HTTP_X_FORWARDED_HOST'] = 'example.net';
        $this->assertNotEquals('example.net', Utils::getSelfHost());

        Utils::setProxyVars(true);
        $this->assertEquals('example.net', Utils::getSelfHost());
    }

    /**
     * Tests the isHTTPS method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::isHTTPS
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testisHTTPS()
    {
        $this->assertFalse(Utils::isHTTPS());

        $_SERVER['HTTPS'] = 'on';
        $this->assertTrue(Utils::isHTTPS());

        unset($_SERVER['HTTPS']);
        $this->assertFalse(Utils::isHTTPS());
        $_SERVER['HTTP_HOST'] = 'example.com:443';
        $this->assertTrue(Utils::isHTTPS());
    }

    /**
     * @covers OneLogin\Saml2\Utils::getSelfURLhost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfurlhostdoubleport()
    {
        Utils::setProxyVars(true);
        $_SERVER['HTTP_HOST'] = 'example.com:8080';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertEquals('http://example.com:82', Utils::getSelfURLhost());

        $_SERVER['HTTP_HOST'] = 'example.com:ok';
        $_SERVER['HTTP_X_FORWARDED_PORT'] = 82;
        $this->assertEquals('http://example.com:82', Utils::getSelfURLhost());
    }

    /**
     * @covers OneLogin\Saml2\Utils::getSelfPort
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetselfPort()
    {
        $this->assertNull(Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:ok';
        $this->assertNull(Utils::getSelfPort());

        $_SERVER['HTTP_HOST'] = 'example.org:8080';
        $this->assertEquals(8080, Utils::getSelfPort());

        $_SERVER["SERVER_PORT"] = 80;
        $this->assertEquals(80, Utils::getSelfPort());

        $_SERVER["HTTP_X_FORWARDED_PORT"] = 443;
        $this->assertEquals(80, Utils::getSelfPort());

        Utils::setProxyVars(true);
        $this->assertEquals(443, Utils::getSelfPort());

        Utils::setSelfPort(8080);
        $this->assertEquals(8080, Utils::getSelfPort());
    }

    /**
     * @covers OneLogin\Saml2\Utils::setSelfProtocol
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetselfprotocol()
    {
        $this->assertFalse(Utils::isHTTPS());

        Utils::setSelfProtocol('https');
        $this->assertTrue(Utils::isHTTPS());
    }

    /**
     * @covers OneLogin\Saml2\Utils::setBaseURLPath
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testSetBaseURLPath()
    {
        $this->assertNull(Utils::getBaseURLPath());

        Utils::setBaseURLPath('sp');
        $this->assertEquals('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('sp/');
        $this->assertEquals('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('/sp');
        $this->assertEquals('/sp/', Utils::getBaseURLPath());

        Utils::setBaseURLPath('/sp/');
        $this->assertEquals('/sp/', Utils::getBaseURLPath());
    }

    /**
     * @covers OneLogin\Saml2\Utils::setBaseURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
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

        Utils::setBaseURL("no-valid-url");
        $this->assertEquals('https', Utils::getSelfProtocol());
        $this->assertEquals('sp.example.com', Utils::getSelfHost());
        $this->assertNull(Utils::getSelfPort());
        $this->assertNull(Utils::getBaseURLPath());

        $this->assertEquals($expectedUrlNQ, Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ, Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl, Utils::getSelfURL());

        Utils::setBaseURL("http://anothersp.example.com:81/example2/");
        $expectedUrlNQ2 = 'http://anothersp.example.com:81/example2/route.php';
        $expectedRoutedUrlNQ2 = 'http://anothersp.example.com:81/example2/route.php';
        $expectedUrl2 = 'http://anothersp.example.com:81/example2/route.php?x=test';

        $this->assertEquals('http', Utils::getSelfProtocol());
        $this->assertEquals('anothersp.example.com', Utils::getSelfHost());
        $this->assertEquals('81', Utils::getSelfPort());
        $this->assertEquals('/example2/', Utils::getBaseURLPath());

        $this->assertEquals($expectedUrlNQ2, Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ2, Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl2, Utils::getSelfURL());

        $_SERVER['PATH_INFO'] = '/test';
        $expectedUrlNQ2 = 'http://anothersp.example.com:81/example2/route.php/test';

        $this->assertEquals($expectedUrlNQ2, Utils::getSelfURLNoQuery());
        $this->assertEquals($expectedRoutedUrlNQ2, Utils::getSelfRoutedURLNoQuery());
        $this->assertEquals($expectedUrl2, Utils::getSelfURL());
    }

    /**
     * Tests the getSelfURLhost method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getSelfURLhost
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURLhost()
    {
        $hostname = Utils::getSelfHost();

        $this->assertEquals("http://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '80';
        $this->assertEquals("http://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '81';
        $this->assertEquals("http://$hostname:81", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $this->assertEquals("https://$hostname", Utils::getSelfURLhost());

        unset($_SERVER['SERVER_PORT']);
        $_SERVER['HTTPS'] = 'on';
        $this->assertEquals("https://$hostname", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '444';
        $this->assertEquals("https://$hostname:444", Utils::getSelfURLhost());

        $_SERVER['SERVER_PORT'] = '443';
        $_SERVER['REQUEST_URI'] = '/onelogin';
        $this->assertEquals("https://$hostname", Utils::getSelfURLhost());

        $_SERVER['REQUEST_URI'] = 'https://$hostname/onelogin/sso';
        $this->assertEquals("https://$hostname", Utils::getSelfURLhost());
    }

    /**
     * Tests the getSelfURL method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getSelfURL
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURL()
    {
        $url = Utils::getSelfURLhost();

        $this->assertEquals($url, Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/index.php';
        $this->assertEquals($url.'/index.php', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertEquals($url.'/test/index.php?testing', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = '/test/index.php?testing';
        $this->assertEquals($url.'/test/index.php?testing', Utils::getSelfURL());

        $_SERVER['REQUEST_URI'] = 'https://example.com/testing';
        $this->assertEquals($url.'/testing', Utils::getSelfURL());
    }

    /**
     * Tests the getSelfURLNoQuery method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getSelfURLNoQuery
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testGetSelfURLNoQuery()
    {
        $url = Utils::getSelfURLhost();
        $url .= $_SERVER['SCRIPT_NAME'];

        $this->assertEquals($url, Utils::getSelfURLNoQuery());

        $_SERVER['PATH_INFO'] = '/test';
        $this->assertEquals($url.'/test', Utils::getSelfURLNoQuery());
    }

    /**
     * Tests the getSelfRoutedURLNoQuery method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getSelfRoutedURLNoQuery
     *
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function getSelfRoutedURLNoQuery()
    {
        $url = Utils::getSelfURLhost();
        $_SERVER['REQUEST_URI'] = 'example1/route?x=test';
        $_SERVER['QUERY_STRING'] = '?x=test';

        $url .= 'example1/route';

        $this->assertEquals($url, Utils::getSelfRoutedURLNoQuery());
    }

    /**
     * Gets the status of a message
     *
     * @covers OneLogin\Saml2\Utils::getStatus
     */
    public function testGetStatus()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response1.xml.base64'));
        $dom = new DOMDocument();
        $dom->loadXML($xml);

        $status = Utils::getStatus($dom);
        $this->assertEquals(Constants::STATUS_SUCCESS, $status['code']);

        $xml2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responder.xml.base64'));
        $dom2 = new DOMDocument();
        $dom2->loadXML($xml2);

        $status2 = Utils::getStatus($dom2);
        $this->assertEquals(Constants::STATUS_RESPONDER, $status2['code']);
        $this->assertEmpty($status2['msg']);

        $xml3 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/status_code_responer_and_msg.xml.base64'));
        $dom3 = new DOMDocument();
        $dom3->loadXML($xml3);

        $status3 = Utils::getStatus($dom3);
        $this->assertEquals(Constants::STATUS_RESPONDER, $status3['code']);
        $this->assertEquals('something_is_wrong', $status3['msg']);

        $xmlInv = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status.xml.base64'));
        $domInv = new DOMDocument();
        $domInv->loadXML($xmlInv);

        try {
            $statusInv = Utils::getStatus($domInv);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertEquals('Missing Status on response', $e->getMessage());
        }

        $xmlInv2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_status_code.xml.base64'));
        $domInv2 = new DOMDocument();
        $domInv2->loadXML($xmlInv2);

        try {
            $statusInv2 = Utils::getStatus($domInv2);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertEquals('Missing Status Code on response', $e->getMessage());
        }
    }

    /**
     * Tests the parseDuration method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::parseDuration
     */
    public function testParseDuration()
    {
        $duration = 'PT1393462294S';
        $timestamp = 1393876825;

        $parsedDuration = Utils::parseDuration($duration, $timestamp);
        $this->assertEquals(2787339119, $parsedDuration);

        $parsedDuration2 = Utils::parseDuration($duration);

        $this->assertTrue($parsedDuration2 > $parsedDuration);

        $invalidDuration = 'PT1Y';
        try {
            $parsedDuration3 = Utils::parseDuration($invalidDuration);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid ISO 8601 duration', $e->getMessage());
        }

        $newDuration = 'P1Y1M';
        $parsedDuration4 = Utils::parseDuration($newDuration, $timestamp);
        $this->assertEquals(1428091225, $parsedDuration4);

        $negDuration = '-P14M';
        $parsedDuration5 = Utils::parseDuration($negDuration, $timestamp);
        $this->assertEquals(1357243225, $parsedDuration5);
    }

    /**
     * Tests the parseSAML2Time method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::parseSAML2Time
     */
    public function testParseSAML2Time()
    {
        $time = 1386650371;
        $SAMLTime = '2013-12-10T04:39:31Z';
        $this->assertEquals($time, Utils::parseSAML2Time($SAMLTime));

        try {
            Utils::parseSAML2Time('invalidSAMLTime');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Invalid SAML2 timestamp passed', $e->getMessage());
        }

        // Now test if toolkit supports miliseconds
        $SAMLTime2 = '2013-12-10T04:39:31.120Z';
        $this->assertEquals($time, Utils::parseSAML2Time($SAMLTime2));
    }

    /**
     * Tests the parseTime2SAML method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::parseTime2SAML
     */
    public function testParseTime2SAML()
    {
        $time = 1386650371;
        $SAMLTime = '2013-12-10T04:39:31Z';
        $this->assertEquals($SAMLTime, Utils::parseTime2SAML($time));

        try {
            Utils::parseTime2SAML('invalidtime');
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Failed to parse time string', $e->getMessage());
        }
    }

    /**
     * Tests the getExpireTime method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::getExpireTime
     */
    public function testGetExpireTime()
    {
        $this->assertNull(Utils::getExpireTime());

        $this->assertNotNull(Utils::getExpireTime('PT1393462294S'));

        $this->assertEquals('1418186371', Utils::getExpireTime('PT1393462294S', '2014-12-10T04:39:31Z'));
        $this->assertEquals('1418186371', Utils::getExpireTime('PT1393462294S', 1418186371));

        $this->assertNotEquals('1418186371', Utils::getExpireTime('PT1393462294S', '2012-12-10T04:39:31Z'));
    }

    /**
     * Tests the query method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::query
     */
    public function testQuery()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_response.xml.base64'));
        $dom = new DOMDocument();
        $dom->loadXML($xml);

        $assertionNodes = Utils::query($dom, '/samlp:Response/saml:Assertion');
        $this->assertEquals(1, $assertionNodes->length);
        $assertion = $assertionNodes->item(0);
        $this->assertEquals('saml:Assertion', $assertion->tagName);

        $attributeStatementNodes = Utils::query($dom, '/samlp:Response/saml:Assertion/saml:AttributeStatement');
        $this->assertEquals(1, $attributeStatementNodes->length);
        $attributeStatement = $attributeStatementNodes->item(0);
        $this->assertEquals('saml:AttributeStatement', $attributeStatement->tagName);

        $attributeStatementNodes2 = Utils::query($dom, './saml:AttributeStatement', $assertion);
        $this->assertEquals(1, $attributeStatementNodes2->length);
        $attributeStatement2 = $attributeStatementNodes2->item(0);
        $this->assertEquals($attributeStatement, $attributeStatement2);

        $signatureResNodes = Utils::query($dom, '/samlp:Response/ds:Signature');
        $this->assertEquals(1, $signatureResNodes->length);
        $signatureRes = $signatureResNodes->item(0);
        $this->assertEquals('ds:Signature', $signatureRes->tagName);

        $signatureNodes = Utils::query($dom, '/samlp:Response/saml:Assertion/ds:Signature');
        $this->assertEquals(1, $signatureNodes->length);
        $signature = $signatureNodes->item(0);
        $this->assertEquals('ds:Signature', $signature->tagName);

        $signatureNodes2 = Utils::query($dom, './ds:Signature', $assertion);
        $this->assertEquals(1, $signatureNodes2->length);
        $signature2 = $signatureNodes2->item(0);
        $this->assertEquals($signature->textContent, $signature2->textContent);
        $this->assertNotEquals($signatureRes->textContent, $signature2->textContent);

        $signatureNodes3 = Utils::query($dom, './ds:SignatureValue', $assertion);
        $this->assertEquals(0, $signatureNodes3->length);

        $signatureNodes4 = Utils::query($dom, './ds:Signature/ds:SignatureValue', $assertion);
        $this->assertEquals(1, $signatureNodes4->length);

        $signatureNodes5 = Utils::query($dom, './/ds:SignatureValue', $assertion);
        $this->assertEquals(1, $signatureNodes5->length);
    }

    /**
     * Tests the generateNameId method of the Utils
     * Adding a SPNameQualifier
     *
     * @covers OneLogin\Saml2\Utils::generateNameId
     */
    public function testGenerateNameIdWithSPNameQualifier()
    {
        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';
        $nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

        $nameId = Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat
        );

        $expectedNameId = '<saml:NameID SPNameQualifier="http://stuff.com/endpoints/metadata.php" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';

        $this->assertEquals($nameId, $expectedNameId);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $x509cert = $settingsInfo['idp']['x509cert'];
        $key = Utils::formatCert($x509cert);

        $nameIdEnc = Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat,
            $key
        );

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>';
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);

        // Check AES128_GCM support

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue>';

        $nameIdEnc = Utils::generateNameId(
            $nameIdValue,
            $entityId,
            $nameIDFormat,
            $key,
            null,
            XMLSecurityKey::AES128_GCM
        );
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);
    }

    /**
    * Tests the generateNameId method of the Utils
    *
    * @covers OneLogin\Saml2\Utils::generateNameId
    */
    public function testGenerateNameIdWithoutFormat()
    {
        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $nameId = Utils::generateNameId(
            $nameIdValue,
            null,
            null
        );
        $expectedNameId = '<saml:NameID>ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';
        $this->assertEquals($nameId, $expectedNameId);
    }

    /**
     * Tests the generateNameId method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::generateNameId
     */
    public function testGenerateNameIdWithoutSPNameQualifier()
    {
        //$xml = '<root xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.$decrypted.'</root>';
        //$newDoc = new DOMDocument();

        $nameIdValue = 'ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde';
        $entityId = 'http://stuff.com/endpoints/metadata.php';
        $nameIDFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

        $nameId = Utils::generateNameId(
            $nameIdValue,
            null,
            $nameIDFormat
        );

        $expectedNameId = '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">ONELOGIN_ce998811003f4e60f8b07a311dc641621379cfde</saml:NameID>';

        $this->assertEquals($nameId, $expectedNameId);

        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $x509cert = $settingsInfo['idp']['x509cert'];
        $key = Utils::formatCert($x509cert);

        $nameIdEnc = Utils::generateNameId(
            $nameIdValue,
            null,
            $nameIDFormat,
            $key
        );

        $nameidExpectedEnc = '<saml:EncryptedID><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/><dsig:KeyInfo xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/><xenc:CipherData><xenc:CipherValue>';
        $this->assertContains($nameidExpectedEnc, $nameIdEnc);
    }

    /**
     * Tests the deleteLocalSession method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::deleteLocalSession
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

            Utils::deleteLocalSession();
            $this->assertEmpty($_SESSION);
            $this->assertFalse(isset($_SESSION['samltest']));

            $prev = error_reporting(0);
            session_start();
            error_reporting($prev);

            $_SESSION['samltest'] = true;
            Utils::deleteLocalSession();
            $this->assertEmpty($_SESSION);
            $this->assertFalse(isset($_SESSION['samltest']));
        }
    }

    /**
     * Tests the isSessionStarted method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::isSessionStarted
     */
    public function testisSessionStarted()
    {
        if (getenv("TRAVIS")) {
            // Can't test that on TRAVIS
            $this->markTestSkipped("Can't test that on TRAVIS");
        } else {
            $this->assertFalse(Utils::isSessionStarted());

            $prev = error_reporting(0);
            session_start();
            error_reporting($prev);

            $this->assertTrue(Utils::isSessionStarted());
        }
    }


    /**
     * Tests the calculateX509Fingerprint method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::calculateX509Fingerprint
     */
    public function testCalculateX509Fingerprint()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $certPath = $settings->getCertPath();

        $key = file_get_contents($certPath.'sp.key');
        $cert = file_get_contents($certPath.'sp.crt');

        $this->assertNull(Utils::calculateX509Fingerprint($key));

        $this->assertNull(Utils::calculateX509Fingerprint(""));

        $this->assertNull(Utils::calculateX509Fingerprint($settingsInfo['idp']['x509cert']));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint(Utils::formatCert($settingsInfo['idp']['x509cert'])));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint($cert));

        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::calculateX509Fingerprint($cert, 'sha1'));

        $this->assertEquals('c51cfa06c7a49767f6eab18238eae1c56708e29264da3d11f538a12cd2c357ba', Utils::calculateX509Fingerprint($cert, 'sha256'));

        $this->assertEquals('bc5826e6f9429247254bae5e3c650e6968a36a62d23075eb168134978d88600559c10830c28711b2c29c7947c0c2eb1d', Utils::calculateX509Fingerprint($cert, 'sha384'));

        $this->assertEquals('3db29251b97559c67988ea0754cb0573fc409b6f75d89282d57cfb75089539b0bbdb2dcd9ec6e032549ecbc466439d5992e18db2cf5494ca2fe1b2e16f348dff', Utils::calculateX509Fingerprint($cert, 'sha512'));
    }

    /**
     * Tests the formatFingerPrint method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::formatFingerPrint
     */
    public function testFormatFingerPrint()
    {
        $fingerPrint1 = 'AF:E7:1C:28:EF:74:0B:C8:74:25:BE:13:A2:26:3D:37:97:1D:A1:F9';
        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::formatFingerPrint($fingerPrint1));

        $fingerPrint2 = 'afe71c28ef740bc87425be13a2263d37971da1f9';
        $this->assertEquals('afe71c28ef740bc87425be13a2263d37971da1f9', Utils::formatFingerPrint($fingerPrint2));
    }

    /**
     * Tests the decryptElement method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::decryptElement
     */
    public function testDecryptElement()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);

        $key = $settings->getSPkey();
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
        $seckey->loadKey($key);

        $xmlNameIdEnc = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64'));
        $domNameIdEnc = new DOMDocument();
        $domNameIdEnc->loadXML($xmlNameIdEnc);
        $encryptedNameIDNodes = $domNameIdEnc->getElementsByTagName('EncryptedID');
        $encryptedData = $encryptedNameIDNodes->item(0)->firstChild;
        $decryptedNameId = Utils::decryptElement($encryptedData, $seckey);
        $this->assertEquals('saml:NameID', $decryptedNameId->tagName);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId->nodeValue);

        $xmlAsssertionEnc = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64'));
        $domAsssertionEnc = new DOMDocument();
        $domAsssertionEnc->loadXML($xmlAsssertionEnc);
        $encryptedAssertionEncNodes = $domAsssertionEnc->getElementsByTagName('EncryptedAssertion');
        $encryptedAssertionEncNode = $encryptedAssertionEncNodes->item(0);
        $encryptedDataAssertNodes = $encryptedAssertionEncNode->getElementsByTagName('EncryptedData');
        $encryptedDataAssert = $encryptedDataAssertNodes->item(0);
        $decryptedAssertion = Utils::decryptElement($encryptedDataAssert, $seckey);

        $this->assertEquals('saml:Assertion', $decryptedAssertion->tagName);

        try {
            $res = Utils::decryptElement($encryptedNameIDNodes->item(0), $seckey);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key in message', $e->getMessage());
        }

        $key2 = file_get_contents(TEST_ROOT . '/data/misc/sp2.key');
        $seckey2 = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type'=>'private'));
        $seckey2->loadKey($key2);
        $decryptedNameId2 = Utils::decryptElement($encryptedData, $seckey2);
        $this->assertEquals('saml:NameID', $decryptedNameId2->tagName);
        $this->assertEquals('2de11defd199f8d5bb63f9b7deb265ba5c675c10', $decryptedNameId2->nodeValue);

        $key3 = file_get_contents(TEST_ROOT . '/data/misc/sp2.key');
        $seckey3 = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, array('type'=>'private'));
        $seckey3->loadKey($key3);
        try {
            $res = Utils::decryptElement($encryptedData, $seckey3);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key used to encrypt  the symmetric key for the message', $e->getMessage());
        }

        $xmlNameIdEnc2 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_EncMethod.xml.base64'));
        $domNameIdEnc2 = new DOMDocument();
        $domNameIdEnc2->loadXML($xmlNameIdEnc2);
        $encryptedNameIDNodes2 = $domNameIdEnc2->getElementsByTagName('EncryptedID');
        $encryptedData2 = $encryptedNameIDNodes2->item(0)->firstChild;
        try {
            $res = Utils::decryptElement($encryptedData2, $seckey);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Unable to locate algorithm for this Encrypted Key', $e->getMessage());
        }

        $xmlNameIdEnc3 = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/encrypted_nameID_without_keyinfo.xml.base64'));
        $domNameIdEnc3 = new DOMDocument();
        $domNameIdEnc3->loadXML($xmlNameIdEnc3);
        $encryptedNameIDNodes3 = $domNameIdEnc3->getElementsByTagName('EncryptedID');
        $encryptedData3 = $encryptedNameIDNodes3->item(0)->firstChild;
        try {
            $res = Utils::decryptElement($encryptedData3, $seckey);
            $this->fail('ValidationError was not raised');
        } catch (ValidationError $e) {
            $this->assertContains('Algorithm mismatch between input key and key in message', $e->getMessage());
        }
    }

    /**
     * Tests the addSign method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::addSign
     */
    public function testAddSign()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $key = $settings->getSPkey();
        $cert = $settings->getSPcert();

        $xmlAuthn = base64_decode(file_get_contents(TEST_ROOT . '/data/requests/authn_request.xml.base64'));
        $xmlAuthnSigned = Utils::addSign($xmlAuthn, $key, $cert);
        $this->assertContains('<ds:SignatureValue>', $xmlAuthnSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlAuthnSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>', $xmlAuthnSigned);
        $res = new DOMDocument();
        $res->loadXML($xmlAuthnSigned);
        $dsSignature = $res->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature->tagName);

        $dom = new DOMDocument();
        $dom->loadXML($xmlAuthn);
        $xmlAuthnSigned2 = Utils::addSign($dom, $key, $cert, XMLSecurityKey::RSA_SHA384, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlAuthnSigned2);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"/>', $xmlAuthnSigned2);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlAuthnSigned2);
        $res2 = new DOMDocument();
        $res2->loadXML($xmlAuthnSigned2);
        $dsSignature2 = $res2->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature2->tagName);

        $xmlLogoutReq = base64_decode(file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request.xml.base64'));
        $xmlLogoutReqSigned = Utils::addSign($xmlLogoutReq, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlLogoutReqSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutReqSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutReqSigned);
        $res3 = new DOMDocument();
        $res3->loadXML($xmlLogoutReqSigned);
        $dsSignature3 = $res3->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature3->tagName);

        $xmlLogoutRes = base64_decode(file_get_contents(TEST_ROOT . '/data/logout_responses/logout_response.xml.base64'));
        $xmlLogoutResSigned = Utils::addSign($xmlLogoutRes, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlLogoutResSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlLogoutResSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlLogoutResSigned);
        $res4 = new DOMDocument();
        $res4->loadXML($xmlLogoutResSigned);
        $dsSignature4 = $res4->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertContains('ds:Signature', $dsSignature4->tagName);

        $xmlMetadata = file_get_contents(TEST_ROOT . '/data/metadata/metadata_settings1.xml');
        $xmlMetadataSigned = Utils::addSign($xmlMetadata, $key, $cert, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512);
        $this->assertContains('<ds:SignatureValue>', $xmlMetadataSigned);
        $this->assertContains('<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>', $xmlMetadataSigned);
        $this->assertContains('<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha512"/>', $xmlMetadataSigned);
        $res5 = new DOMDocument();
        $res5->loadXML($xmlMetadataSigned);
        $dsSignature5 = $res5->firstChild->firstChild;
        $this->assertContains('ds:Signature', $dsSignature5->tagName);
    }

    /**
     * Tests the validateSign method of the Utils
     *
     * @covers OneLogin\Saml2\Utils::validateSign
     */
    public function testValidateSign()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $settings = new Settings($settingsInfo);
        $idpData = $settings->getIdPData();
        $cert = $idpData['x509cert'];
        $fingerprint = Utils::calculateX509Fingerprint($cert);
        $fingerprint256 = Utils::calculateX509Fingerprint($cert, 'sha256');

        $xmlMetadataSigned = file_get_contents(TEST_ROOT . '/data/metadata/signed_metadata_settings1.xml');
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, $cert));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, $fingerprint));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha1'));
        $this->assertFalse(Utils::validateSign($xmlMetadataSigned, null, $fingerprint, 'sha256'));
        $this->assertTrue(Utils::validateSign($xmlMetadataSigned, null, $fingerprint256, 'sha256'));

        $xmlResponseMsgSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64'));
        $this->assertTrue(Utils::validateSign($xmlResponseMsgSigned, $cert));
        $this->assertTrue(Utils::validateSign($xmlResponseMsgSigned, null, $fingerprint));

        $xmlResponseAssertSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64'));
        $this->assertTrue(Utils::validateSign($xmlResponseAssertSigned, $cert));
        $this->assertTrue(Utils::validateSign($xmlResponseAssertSigned, null, $fingerprint));

        $xmlResponseDoubleSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/double_signed_response.xml.base64'));
        $this->assertTrue(Utils::validateSign($xmlResponseDoubleSigned, $cert));
        $this->assertTrue(Utils::validateSign($xmlResponseDoubleSigned, null, $fingerprint));

        $dom = new DOMDocument();
        $dom->loadXML($xmlResponseMsgSigned);
        $this->assertTrue(Utils::validateSign($dom, $cert));

        $dom->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        try {
            $this->assertFalse(Utils::validateSign($dom, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference validation failed', $e->getMessage());
        }

        $dom2 = new DOMDocument();
        $dom2->loadXML($xmlResponseMsgSigned);
        $assertElem = $dom2->firstChild->firstChild->nextSibling->nextSibling;
        $this->assertTrue(Utils::validateSign($assertElem, $cert));

        $dom3 = new DOMDocument();
        $dom3->loadXML($xmlResponseMsgSigned);
        $dom3->firstChild->firstChild->nodeValue = 'https://example.com/other-idp';
        $assertElem2 = $dom3->firstChild->firstChild->nextSibling->nextSibling;
        try {
            $this->assertTrue(Utils::validateSign($assertElem2, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference validation failed', $e->getMessage());
        }

        $invalidFingerprint = 'afe71c34ef740bc87434be13a2263d31271da1f9';
        $this->assertFalse(Utils::validateSign($xmlMetadataSigned, null, $invalidFingerprint));

        $noSigned = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_signature.xml.base64'));
        try {
            $this->assertFalse(Utils::validateSign($noSigned, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Cannot locate Signature Node', $e->getMessage());
        }

        $noKey = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/no_key.xml.base64'));
        try {
            $this->assertFalse(Utils::validateSign($noKey, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('We have no idea about the key', $e->getMessage());
        }

        $signatureWrapping = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/invalids/signature_wrapping_attack.xml.base64'));
        try {
            $this->assertFalse(Utils::validateSign($signatureWrapping, $cert));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertContains('Reference validation failed', $e->getMessage());
        }
    }
}
