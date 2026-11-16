<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class RedirectQueryTest extends \PHPUnit\Framework\TestCase
{
    private $_server;

    protected function setUp(): void
    {
        $this->_server = $_SERVER;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->_server;
    }

    /** @dataProvider originalParameterCases */
    public function testExtractOriginalParameter($query, $name, $expected)
    {
        $_SERVER['QUERY_STRING'] = $query;
        $this->assertSame($expected, Utils::extractOriginalQueryParam($name));
    }

    public static function originalParameterCases()
    {
        return array(
            array('other=RelayState=wrong&RelayState=right%2fvalue', 'RelayState', 'right%2fvalue'),
            array('notRelayState=wrong&RelayState=right', 'RelayState', 'right'),
            array('RelayState=&SigAlg=algorithm', 'RelayState', ''),
            array('RelayState=a=b=c&SigAlg=algorithm', 'RelayState', 'a=b=c'),
            array('RelayState=0&SigAlg=algorithm', 'RelayState', '0'),
            array('other=some-value', 'RelayState', ''),
            array('RelayState', 'RelayState', ''),
            array('', 'RelayState', ''),
        );
    }

    /** @dataProvider signedParameterCases */
    public function testReservedNamesInValuesDoNotInvalidateSignatures($messageType, $relayState)
    {
        list($getData, $idpData) = $this->signedQuery($messageType, $relayState);
        // An unrelated field must not shadow the real message parameter.
        $_SERVER['QUERY_STRING'] = 'other='.$messageType.'=wrong&notSignature=ignored&'.$_SERVER['QUERY_STRING'];
        $this->assertTrue(Utils::validateBinarySign($messageType, $getData, $idpData, true));
    }

    public static function signedParameterCases()
    {
        $cases = array();
        foreach (array('SAMLRequest', 'SAMLResponse') as $messageType) {
            foreach (array('SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature', '', 'https://example.test/path?a=b') as $relayState) {
                $cases[] = array($messageType, $relayState);
            }
        }
        return $cases;
    }

    /** @dataProvider duplicateParameterCases */
    public function testActualDuplicateParametersAreRejected($name)
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] .= '&'.$name.'=one&'.$name.'=two';
        $this->expectException(Error::class);
        $this->expectExceptionMessage('Duplicate parameter in query string');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    public static function duplicateParameterCases()
    {
        return array(array('SAMLRequest'), array('SAMLResponse'), array('RelayState'), array('SigAlg'), array('Signature'));
    }

    public function testBothMessageParametersAreRejected()
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] .= '&SAMLResponse=other';
        $this->expectException(Error::class);
        $this->expectExceptionMessage('Both SAMLRequest and SAMLResponse provided');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    public function testTamperedRelayStateIsRejected()
    {
        list($getData, $idpData) = $this->signedQuery('SAMLResponse', 'home');
        $_SERVER['QUERY_STRING'] = str_replace('RelayState=home', 'RelayState=changed', $_SERVER['QUERY_STRING']);
        $getData['RelayState'] = 'changed';
        $this->assertFalse(Utils::validateBinarySign('SAMLResponse', $getData, $idpData, true));
    }

    private function signedQuery($messageType, $relayState)
    {
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        $key->loadKey(file_get_contents(TEST_ROOT.'/data/customPath/certs/sp.key'));
        $encode = function ($value) {
            return preg_replace_callback(
                '/%[0-9A-F]{2}/',
                function ($match) {
                    return strtolower($match[0]);
                },
                urlencode($value)
            );
        };
        $query = $messageType.'='.$encode(base64_encode('synthetic-message'));
        $query .= '&RelayState='.$encode($relayState).'&SigAlg='.$encode(XMLSecurityKey::RSA_SHA256);
        $_SERVER['QUERY_STRING'] = $query.'&Signature='.$encode(base64_encode($key->signData($query)));
        parse_str($_SERVER['QUERY_STRING'], $getData);
        return array($getData, array('x509cert' => file_get_contents(TEST_ROOT.'/data/customPath/certs/sp.crt')));
    }
}
