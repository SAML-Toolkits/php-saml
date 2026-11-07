<?php

/**
 * Tests of the redirections that the toolkit executes when $stay is false: the HTTP response has the
 * status, the Location (the target URL) and the cache headers of the redirection, and exit() ends the
 * script.
 *
 * A redirection can not be executed inside the PHPUnit process (header() fails because PHPUnit already
 * sent output, or exit() ends the process), so each case runs in a PHP built-in web server (with the
 * router tests/redirection_router.php) and the test checks the real HTTP response. The other tests
 * check the target URLs with $stay; these ones check that the redirection sends the same URL.
 */
class OneLogin_Saml2_RedirectionTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var resource|null Process of the PHP built-in web server
     */
    private static $_server;

    /**
     * @var int Port of the PHP built-in web server
     */
    private static $_port;

    /**
     * Starts the PHP built-in web server, with the PHP binary that runs the tests. If it can not be
     * started the tests fail (they are not skipped)
     *
     * @throws Exception
     */
    public static function setUpBeforeClass()
    {
        // A free port
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($socket === false) {
            throw new Exception("Unable to find a free port: $errstr");
        }
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        self::$_port = (int) substr($name, strrpos($name, ':') + 1);

        $command = 'exec ' . escapeshellarg(PHP_BINARY) . ' -S 127.0.0.1:' . self::$_port
            . ' -t ' . escapeshellarg(TEST_ROOT) . ' ' . escapeshellarg(TEST_ROOT . '/redirection_router.php');
        $descriptors = array(
            0 => array('file', '/dev/null', 'r'),
            1 => array('file', '/dev/null', 'w'),
            2 => array('file', '/dev/null', 'w'),
        );
        self::$_server = proc_open($command, $descriptors, $pipes, TEST_ROOT);
        if (!is_resource(self::$_server)) {
            throw new Exception('Unable to start the PHP built-in web server');
        }

        // Wait until it accepts connections
        for ($i = 0; $i < 200; $i++) {
            $connection = @fsockopen('127.0.0.1', self::$_port, $errno, $errstr, 0.1);
            if ($connection !== false) {
                fclose($connection);
                return;
            }
            usleep(50000);
        }
        self::tearDownAfterClass();
        throw new Exception('The PHP built-in web server did not start');
    }

    /**
     * Stops the PHP built-in web server
     */
    public static function tearDownAfterClass()
    {
        if (is_resource(self::$_server)) {
            proc_terminate(self::$_server);
            proc_close(self::$_server);
        }
        self::$_server = null;
    }

    /**
     * Requests a case of tests/redirection_router.php (the redirection is not followed)
     *
     * @param string $case       The case
     * @param array  $parameters Other parameters of the request
     *
     * @return array The response: the status line, the headers (lowercase name => value) and the body
     */
    private function request($case, $parameters = array())
    {
        // The request is sent through a socket, not with the http:// stream wrapper: in PHP 5.x and 7.1
        // the wrapper drops the header lines of 1024 bytes or more, and the Location of a redirection
        // (a signed AuthnRequest, for example) can be that long
        $socket = @fsockopen('127.0.0.1', self::$_port, $errno, $errstr, 10);
        $this->assertNotFalse($socket, "The request of the case $case failed: $errstr");
        stream_set_timeout($socket, 10);
        $query = http_build_query(array_merge(array('case' => $case), $parameters));
        fwrite($socket, "GET /?$query HTTP/1.0\r\nHost: 127.0.0.1:" . self::$_port . "\r\nConnection: close\r\n\r\n");
        $response = stream_get_contents($socket);
        fclose($socket);

        $parts = explode("\r\n\r\n", $response, 2);
        $this->assertCount(2, $parts, "Invalid response of the case $case: $response");
        list($head, $body) = $parts;

        // The status line and the headers of the response
        $lines = explode("\r\n", $head);
        $headers = array();
        foreach (array_slice($lines, 1) as $line) {
            list($name, $value) = explode(':', $line, 2);
            $headers[strtolower($name)] = trim($value);
        }

        return array('status' => $lines[0], 'headers' => $headers, 'body' => $body);
    }

    /**
     * Checks that the response is the redirection executed by OneLogin_Saml2_Utils::redirect
     *
     * @param array $response The response
     *
     * @return string The target URL (the Location header)
     */
    private function assertRedirection(array $response)
    {
        $this->assertRegExp('#^HTTP/1\.[01] 302 Found$#', $response['status'], $response['body']);
        $this->assertArrayHasKey('location', $response['headers']);
        $this->assertArrayHasKey('pragma', $response['headers']);
        $this->assertArrayHasKey('cache-control', $response['headers']);
        $this->assertEquals('no-cache', $response['headers']['pragma']);
        $this->assertEquals('no-cache, must-revalidate', $response['headers']['cache-control']);
        // exit() ended the script: nothing was executed (and printed) after the redirection
        $this->assertSame('', $response['body']);

        return $response['headers']['location'];
    }

    /**
     * @param string $url A target URL
     *
     * @return string The URL without the query
     */
    private function withoutQuery($url)
    {
        return substr($url, 0, strpos($url, '?'));
    }

    /**
     * @param string $xml A SAML message
     *
     * @return string The message without the values that change in each one (ID and IssueInstant)
     */
    private function withoutVolatileValues($xml)
    {
        return preg_replace(array('/ ID="[^"]*"/', '/ IssueInstant="[^"]*"/'), array(' ID=""', ' IssueInstant=""'), $xml);
    }

    /**
     * Tests the redirect method of the OneLogin_Saml2_Utils
     * Case without $stay: the redirection is executed
     *
     * @covers OneLogin_Saml2_Utils::redirect
     */
    public function testUtilsRedirect()
    {
        $location = $this->assertRedirection($this->request('utils'));

        $this->assertEquals('http://sp.example.com/path?x=1&a=b+c&flag&list[]=1&list[]=2', $location);
        // The URL that is returned with $stay
        $this->assertEquals(
            OneLogin_Saml2_Utils::redirect('http://sp.example.com/path?x=1', array('a' => 'b c', 'flag' => null, 'list' => array('1', '2')), true),
            $location
        );
    }

    /**
     * Tests the redirect method of the OneLogin_Saml2_Utils
     * Case without $stay and a long URL (the Location header is longer than 1024 bytes, as the one of a
     * signed AuthnRequest can be): the whole URL is the target
     *
     * @covers OneLogin_Saml2_Utils::redirect
     */
    public function testUtilsRedirectLongUrl()
    {
        $location = $this->assertRedirection($this->request('utils_long_url'));

        $this->assertGreaterThan(5000, strlen($location));
        $this->assertEquals(OneLogin_Saml2_Utils::redirect('http://sp.example.com/path', array('long' => str_repeat('a', 5000)), true), $location);
    }

    /**
     * Tests the redirect method of the OneLogin_Saml2_Utils
     * Case without $stay and a relative URL: the redirection is executed to the URL of the host of the request
     *
     * @covers OneLogin_Saml2_Utils::redirect
     */
    public function testUtilsRedirectRelativeUrl()
    {
        $location = $this->assertRedirection($this->request('utils_relative'));

        $this->assertEquals('http://127.0.0.1:' . self::$_port . '/relative/path?a=b', $location);
    }

    /**
     * Tests the redirectTo method of the OneLogin_Saml2_Auth class
     * Case without $stay: the redirection is executed
     *
     * @covers OneLogin_Saml2_Auth::redirectTo
     */
    public function testRedirectTo()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $location = $this->assertRedirection($this->request('redirect_to'));

        $this->assertEquals('http://sp2.example.com/target?a=b', $location);
        // The URL that is returned with $stay
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $this->assertEquals($auth->redirectTo('http://sp2.example.com/target', array('a' => 'b'), true), $location);
    }

    /**
     * Tests the redirectTo method of the OneLogin_Saml2_Auth class
     * Case without $stay and without url: the redirection to the RelayState of the request is executed
     *
     * @covers OneLogin_Saml2_Auth::redirectTo
     */
    public function testRedirectToRelayState()
    {
        $relayState = 'http://sp.example.com/relaystate';
        $location = $this->assertRedirection($this->request('redirect_to_relay_state', array('RelayState' => $relayState)));

        $this->assertEquals($relayState, $location);
    }

    /**
     * Tests the login method of the OneLogin_Saml2_Auth class
     * Case without $stay: the redirection to the IdP with the AuthnRequest is executed
     *
     * @covers OneLogin_Saml2_Auth::login
     */
    public function testLogin()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $location = $this->assertRedirection($this->request('login'));

        $ssoUrl = $settingsInfo['idp']['singleSignOnService']['url'];
        $this->assertEquals($ssoUrl, $this->withoutQuery($location));
        $parsedQuery = getParamsFromUrl($location);
        $this->assertEquals(array('extra', 'SAMLRequest', 'RelayState'), array_keys($parsedQuery));
        $this->assertEquals('value', $parsedQuery['extra']);
        $this->assertEquals('http://sp.example.com/relaystate', $parsedQuery['RelayState']);

        $request = gzinflate(base64_decode($parsedQuery['SAMLRequest']));
        $dom = new DOMDocument();
        $dom->loadXML($request);
        $this->assertEquals('AuthnRequest', $dom->documentElement->localName);
        $this->assertEquals($ssoUrl, $dom->documentElement->getAttribute('Destination'));

        // The URL that is returned with $stay (but for the ID and the IssueInstant of the AuthnRequest)
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $stayUrl = $auth->login('http://sp.example.com/relaystate', array('extra' => 'value'), false, false, true);
        $stayQuery = getParamsFromUrl($stayUrl);
        $this->assertEquals($this->withoutQuery($stayUrl), $this->withoutQuery($location));
        $this->assertEquals(array_keys($stayQuery), array_keys($parsedQuery));
        $this->assertEquals($stayQuery['RelayState'], $parsedQuery['RelayState']);
        $this->assertEquals(
            $this->withoutVolatileValues(gzinflate(base64_decode($stayQuery['SAMLRequest']))),
            $this->withoutVolatileValues($request)
        );
    }

    /**
     * Tests the login method of the OneLogin_Saml2_Auth class
     * Case without $stay and signed AuthnRequest: the redirection has a valid signature
     *
     * @covers OneLogin_Saml2_Auth::login
     */
    public function testLoginSigned()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $location = $this->assertRedirection($this->request('login_signed'));

        $this->assertEquals($settingsInfo['idp']['singleSignOnService']['url'], $this->withoutQuery($location));
        $parsedQuery = getParamsFromUrl($location);
        $this->assertEquals(array('SAMLRequest', 'RelayState', 'SigAlg', 'Signature'), array_keys($parsedQuery));
        $this->assertEquals(XMLSecurityKey::RSA_SHA1, $parsedQuery['SigAlg']);

        // The signature covers the parameters as they were sent (url-encoded)
        $rawParameters = array();
        foreach (explode('&', parse_url($location, PHP_URL_QUERY)) as $parameter) {
            list($name, $value) = explode('=', $parameter, 2);
            $rawParameters[$name] = $value;
        }
        $signedQuery = 'SAMLRequest=' . $rawParameters['SAMLRequest'] . '&RelayState=' . $rawParameters['RelayState'] . '&SigAlg=' . $rawParameters['SigAlg'];

        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $spKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'public'));
        $spKey->loadKey($settings->getSPcert(), false, true);
        $this->assertEquals(1, $spKey->verifySignature($signedQuery, base64_decode($parsedQuery['Signature'])));
        $this->assertEquals(0, $spKey->verifySignature($signedQuery . 'x', base64_decode($parsedQuery['Signature'])));
    }

    /**
     * Tests the logout method of the OneLogin_Saml2_Auth class
     * Case without $stay: the redirection to the IdP with the LogoutRequest is executed
     *
     * @covers OneLogin_Saml2_Auth::logout
     */
    public function testLogout()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $location = $this->assertRedirection($this->request('logout'));

        $this->assertEquals($settingsInfo['idp']['singleLogoutService']['url'], $this->withoutQuery($location));
        $parsedQuery = getParamsFromUrl($location);
        $this->assertEquals(array('SAMLRequest', 'RelayState'), array_keys($parsedQuery));
        $this->assertEquals('http://sp.example.com/relaystate', $parsedQuery['RelayState']);

        $request = gzinflate(base64_decode($parsedQuery['SAMLRequest']));
        $this->assertEquals('my_name_id', OneLogin_Saml2_LogoutRequest::getNameId($request));
        $this->assertEquals(array('_51be37965feb5579d803141076936dc2e9d1d98ebf'), OneLogin_Saml2_LogoutRequest::getSessionIndexes($request));

        // The URL that is returned with $stay (but for the ID and the IssueInstant of the LogoutRequest)
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $stayUrl = $auth->logout('http://sp.example.com/relaystate', array(), 'my_name_id', '_51be37965feb5579d803141076936dc2e9d1d98ebf', true);
        $stayQuery = getParamsFromUrl($stayUrl);
        $this->assertEquals($this->withoutQuery($stayUrl), $this->withoutQuery($location));
        $this->assertEquals(array_keys($stayQuery), array_keys($parsedQuery));
        $this->assertEquals(
            $this->withoutVolatileValues(gzinflate(base64_decode($stayQuery['SAMLRequest']))),
            $this->withoutVolatileValues($request)
        );
    }

    /**
     * Tests the processSLO method of the OneLogin_Saml2_Auth class
     * Case without $stay and a valid Logout Request: the redirection to the IdP with the LogoutResponse is executed
     *
     * @covers OneLogin_Saml2_Auth::processSLO
     */
    public function testProcessSLO()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $location = $this->assertRedirection($this->request('process_slo'));

        $this->assertEquals($settingsInfo['idp']['singleLogoutService']['responseUrl'], $this->withoutQuery($location));
        $parsedQuery = getParamsFromUrl($location);
        $this->assertEquals(array('SAMLResponse'), array_keys($parsedQuery));

        $message = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');
        $requestId = OneLogin_Saml2_LogoutRequest::getID(gzinflate(base64_decode($message)));
        $settings = new OneLogin_Saml2_Settings($settingsInfo);
        $logoutResponse = new OneLogin_Saml2_LogoutResponse($settings, $parsedQuery['SAMLResponse']);
        $this->assertEquals($requestId, $logoutResponse->document->documentElement->getAttribute('InResponseTo'));
        $this->assertEquals(OneLogin_Saml2_Constants::STATUS_SUCCESS, $logoutResponse->getStatus());

        // The URL that is returned with $stay (but for the ID and the IssueInstant of the LogoutResponse)
        $_GET['SAMLRequest'] = $message;
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $stayUrl = $auth->processSLO(true, null, false, null, true);
        $stayQuery = getParamsFromUrl($stayUrl);
        $this->assertEquals($this->withoutQuery($stayUrl), $this->withoutQuery($location));
        $this->assertEquals(array_keys($stayQuery), array_keys($parsedQuery));
        $this->assertEquals(
            $this->withoutVolatileValues(gzinflate(base64_decode($stayQuery['SAMLResponse']))),
            $this->withoutVolatileValues($logoutResponse->getXML())
        );
    }
}
