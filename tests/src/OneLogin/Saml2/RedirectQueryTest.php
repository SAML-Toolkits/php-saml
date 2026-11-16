<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Error;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityKey;

class RedirectQueryTest extends \PHPUnit\Framework\TestCase
{
    private $_server;
    private $_get;

    protected function setUp(): void
    {
        $this->_server = $_SERVER;
        $this->_get = $_GET;
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->_server;
        $_GET = $this->_get;
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

    /**
     * PHP gives the name of a reserved parameter to other field names
     * (leading spaces, percent-encoded characters, a NUL byte, an array).
     * The last one replaces the value at $_GET, while the signature is
     * verified over the field with the literal name: such a query is rejected.
     *
     * @dataProvider aliasedParameterCases
     */
    public function testAliasedReservedParametersAreRejected($name, $alias)
    {
        list($signedData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] .= '&'.$alias.'='.urlencode(base64_encode('forged-message'));
        // The GET data comes from the complete query, alias included
        parse_str($_SERVER['QUERY_STRING'], $getData);
        $this->assertNotSame($signedData[$name], $getData[$name], 'PHP does not parse '.$alias.' as '.$name);

        $this->expectException(Error::class);
        $this->expectExceptionMessage('Duplicate parameter in query string');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    public static function aliasedParameterCases()
    {
        $cases = array();
        foreach (array('SAMLRequest', 'RelayState', 'SigAlg', 'Signature') as $name) {
            $aliases = array(
                '%20'.$name,
                '+'.$name,
                '+%20+'.$name,
                '%'.strtoupper(bin2hex($name[0])).substr($name, 1),
                substr($name, 0, -1).'%'.bin2hex(substr($name, -1)),
                $name.'%00',
                $name.'%00suffix',
                $name.'[]',
                $name.'[key]',
                $name.'%5B%5D',
                '%20'.$name.'%00[]',
            );
            foreach ($aliases as $alias) {
                $cases[$name.' as '.$alias] = array($name, $alias);
            }
        }
        return $cases;
    }

    /**
     * An alias is rejected wherever it is, also when PHP keeps the signed value
     * (the alias comes first) or when the alias repeats the signed value.
     */
    public function testHarmlessAliasesAreRejectedToo()
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $signedQuery = $_SERVER['QUERY_STRING'];
        $queries = array(
            '%20SAMLRequest='.urlencode(base64_encode('forged-message')).'&'.$signedQuery,
            $signedQuery.'&%20SAMLRequest='.urlencode($getData['SAMLRequest']),
            $signedQuery.'&%52elayState=home',
        );
        foreach ($queries as $query) {
            $_SERVER['QUERY_STRING'] = $query;
            parse_str($query, $parsedData);
            $this->assertSame($getData, $parsedData);
            try {
                Utils::validateBinarySign('SAMLRequest', $parsedData, $idpData, true);
                $this->fail('Error was not raised for '.$query);
            } catch (Error $e) {
                $this->assertSame('Duplicate parameter in query string', $e->getMessage());
            }
        }
    }

    public function testAliasedOtherMessageParameterIsRejected()
    {
        list(, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] .= '&%53AMLResponse=other';
        parse_str($_SERVER['QUERY_STRING'], $getData);
        $this->assertSame('other', $getData['SAMLResponse']);

        $this->expectException(Error::class);
        $this->expectExceptionMessage('Both SAMLRequest and SAMLResponse provided');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    /**
     * The message that is processed (GET data) has to be the one that was
     * signed (query string), whatever the reason they differ: a parser with
     * other rules (arg_separator.input) or an application that alters $_GET.
     *
     * @dataProvider mismatchedParameterCases
     */
    public function testParsedParametersMustMatchTheQueryString($name, $value)
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', " it's home");
        $this->assertTrue(Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true));

        $getData[$name] = is_callable($value) ? $value($getData[$name]) : $value;
        $this->expectException(Error::class);
        $this->expectExceptionMessage('The '.$name.' parameter does not match the one of the query string');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    public static function mismatchedParameterCases()
    {
        return array(
            'other message' => array('SAMLRequest', base64_encode('forged-message')),
            'message as an array' => array('SAMLRequest', array(base64_encode('forged-message'))),
            'other RelayState' => array('RelayState', 'https://example.test/other'),
            'RelayState with slashes added' => array('RelayState', 'addslashes'),
            'trimmed RelayState' => array('RelayState', 'trim'),
            'other SigAlg' => array('SigAlg', XMLSecurityKey::RSA_SHA1),
        );
    }

    /**
     * The message is only found under its literal name: when it is sent with
     * an alias, there is nothing signed to compare the parsed message with.
     */
    public function testMessageSentOnlyWithAnAliasIsRejected()
    {
        list(, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] = '%53AMLRequest'.substr($_SERVER['QUERY_STRING'], strlen('SAMLRequest'));
        parse_str($_SERVER['QUERY_STRING'], $getData);
        $this->assertArrayHasKey('SAMLRequest', $getData);

        $this->expectException(Error::class);
        $this->expectExceptionMessage('The SAMLRequest parameter does not match the one of the query string');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    /**
     * Compatibility: the query string is split in fields, so anything before
     * the first field name is part of that name. A query string that an
     * application sets itself with the leading '?' validated before.
     */
    public function testQueryStringWithLeadingQuestionMarkIsRejected()
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] = '?'.$_SERVER['QUERY_STRING'];
        $this->assertSame('', Utils::extractOriginalQueryParam('SAMLRequest'));

        $this->expectException(Error::class);
        $this->expectExceptionMessage('The SAMLRequest parameter does not match the one of the query string');
        Utils::validateBinarySign('SAMLRequest', $getData, $idpData, true);
    }

    /**
     * Compatibility: only a field with exactly that name is returned. Before,
     * the name was searched as a substring of the whole query string, and
     * when it was not there the result was an unrelated piece of the query.
     *
     * @dataProvider exactFieldNameCases
     */
    public function testExtractOriginalParameterMatchesOnlyTheExactFieldName($query, $name)
    {
        $_SERVER['QUERY_STRING'] = $query;
        $this->assertSame('', Utils::extractOriginalQueryParam($name));
    }

    public static function exactFieldNameCases()
    {
        return array(
            'end of another name' => array('RelayState=value', 'State'),
            'start of another name' => array('RelayState=value', 'Relay'),
            'name inside a value' => array('other=RelayState=value', 'RelayState'),
            'leading question mark' => array('?RelayState=value', 'RelayState'),
            'missing parameter' => array('SAMLRequest=message&SigAlg=algorithm', 'RelayState'),
            'other case' => array('relaystate=value', 'RelayState'),
            'percent-encoded name' => array('%52elayState=value', 'RelayState'),
            'leading space' => array('%20RelayState=value', 'RelayState'),
            'array' => array('RelayState[]=value', 'RelayState'),
        );
    }

    /**
     * Compatibility: a field without '=' is the parameter with an empty value,
     * as it is for PHP, so it validates a message signed with 'RelayState='.
     */
    public function testReservedParameterWithoutValueIsAnEmptyValue()
    {
        list($getData, $idpData) = $this->signedQuery('SAMLResponse', '');
        $_SERVER['QUERY_STRING'] = str_replace('&RelayState=&', '&RelayState&', $_SERVER['QUERY_STRING'], $count);
        $this->assertSame(1, $count);
        parse_str($_SERVER['QUERY_STRING'], $parsedData);
        $this->assertSame($getData, $parsedData);
        $this->assertTrue(Utils::validateBinarySign('SAMLResponse', $parsedData, $idpData, true));
    }

    /**
     * Compatibility: fields that are not a reserved parameter for PHP are
     * ignored, even if their name has a reserved name inside. Before, they
     * were a "Duplicate parameter in query string".
     *
     * @dataProvider unrelatedFieldCases
     */
    public function testUnrelatedFieldsAreIgnored($field)
    {
        list($getData, $idpData) = $this->signedQuery('SAMLRequest', 'home');
        $_SERVER['QUERY_STRING'] .= '&'.$field;
        parse_str($_SERVER['QUERY_STRING'], $parsedData);
        $this->assertSame($getData, array_intersect_key($parsedData, $getData));
        $this->assertTrue(Utils::validateBinarySign('SAMLRequest', $parsedData, $idpData, true));
    }

    public static function unrelatedFieldCases()
    {
        return array(
            array('xSAMLRequest=value'),
            array('SAMLRequestId=value'),
            array('SAMLRequest_copy=value'),
            array('SAMLRequest.copy=value'),
            array('SAMLRequest%20copy=value'),
            array('x[SAMLRequest]=value'),
            array('samlrequest=value'),
            array('SigAlgorithm=value'),
            array('Signature2=value'),
            array('MyRelayState=RelayState'),
            array('SAMLResponseType=SAMLResponse'),
            array('=SAMLRequest'),
            array('&'),
            array('&=&x=1&'),
            array('utm_source=Signature&utm_medium=SigAlg'),
        );
    }

    /**
     * A signed Logout Request can not be used to make the SP process another
     * one, sent in a field that PHP parses as SAMLRequest as well.
     *
     * @dataProvider forgedLogoutRequestCases
     */
    public function testProcessSLOWithAnAliasedLogoutRequest($alias)
    {
        $settingsInfo = $this->signedMessagesSettings();
        $auth = new Auth($settingsInfo);
        $deleted = 0;
        $deleteSession = function () use (&$deleted) {
            $deleted++;
        };

        // The Logout Request signed by the IdP is accepted
        $this->signedQuery('SAMLRequest', 'home', gzdeflate($this->logoutRequest('signed-user')));
        $signedQuery = $_SERVER['QUERY_STRING'];
        parse_str($signedQuery, $_GET);
        $targetUrl = $auth->processSLO(false, null, true, $deleteSession, true);
        $this->assertSame(array(), $auth->getErrors());
        $this->assertSame(1, $deleted);
        $this->assertStringContainsString($settingsInfo['idp']['singleLogoutService']['responseUrl'], $targetUrl);
        $this->assertStringContainsString('signed-user', $auth->getLastRequestXML());

        // The same signed query with a forged Logout Request appended is not
        $forged = urlencode(base64_encode(gzdeflate($this->logoutRequest('forged-user'))));
        $_SERVER['QUERY_STRING'] = $signedQuery.'&'.$alias.'='.$forged.'&%52elayState='.urlencode('https://attacker.example.test/');
        parse_str($_SERVER['QUERY_STRING'], $_GET);
        $this->assertStringContainsString('forged-user', gzinflate(base64_decode($_GET['SAMLRequest'])));

        $targetUrl = $auth->processSLO(false, null, true, $deleteSession, true);
        $this->assertNull($targetUrl);
        $this->assertSame(array('invalid_logout_request'), $auth->getErrors());
        $this->assertSame('Duplicate parameter in query string', $auth->getLastErrorReason());
        $this->assertSame(1, $deleted);
    }

    public static function forgedLogoutRequestCases()
    {
        return array(
            'leading space' => array('%20SAMLRequest'),
            'plus sign' => array('+SAMLRequest'),
            'percent-encoded name' => array('%53AMLRequest'),
            'NUL byte' => array('SAMLRequest%00'),
        );
    }

    private function signedMessagesSettings()
    {
        include TEST_ROOT.'/settings/settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['security']['wantMessagesSigned'] = true;
        $settingsInfo['idp']['x509cert'] = file_get_contents(TEST_ROOT.'/data/customPath/certs/sp.crt');
        return $settingsInfo;
    }

    private function logoutRequest($nameId)
    {
        return '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            .' ID="ONELOGIN_'.sha1($nameId).'" Version="2.0" IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'"'
            .' Destination="'.Utils::getSelfURLNoQuery().'">'
            .'<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            .'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">'.$nameId.'</saml:NameID>'
            .'</samlp:LogoutRequest>';
    }

    private function signedQuery($messageType, $relayState, $message = 'synthetic-message')
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
        $query = $messageType.'='.$encode(base64_encode($message));
        $query .= '&RelayState='.$encode($relayState).'&SigAlg='.$encode(XMLSecurityKey::RSA_SHA256);
        $_SERVER['QUERY_STRING'] = $query.'&Signature='.$encode(base64_encode($key->signData($query)));
        parse_str($_SERVER['QUERY_STRING'], $getData);
        return array($getData, array('x509cert' => file_get_contents(TEST_ROOT.'/data/customPath/certs/sp.crt')));
    }
}
