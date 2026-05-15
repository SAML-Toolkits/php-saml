<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

/**
 * Reproduces issue #629 (reverse proxy strips an X-Forwarded-Prefix
 * before the request reaches the SP) and demonstrates that the
 * problem can be fully resolved using the public Utils API.
 *
 * Scenario:
 *   IdP signs Destination = https://domain.com/portal/connect/azure/check
 *   User's browser hits   = https://domain.com/portal/connect/azure/check
 *   Reverse proxy strips "/portal" prefix before forwarding to the app.
 *   App server therefore observes:
 *     HTTP_HOST              = domain.com
 *     REQUEST_URI            = /connect/azure/check     (no /portal!)
 *     SERVER_PORT            = 80                       (TLS terminated upstream)
 *     HTTPS                  unset
 *     HTTP_X_FORWARDED_PROTO = https
 *     HTTP_X_FORWARDED_PORT  = 443
 *     HTTP_X_FORWARDED_PREFIX = /portal                 (not consumed by toolkit)
 *
 * Without configuration, Utils::getSelfRoutedURLNoQuery() returns
 *   http://domain.com/connect/azure/check
 * which does not match the signed Destination, so the SP rejects a
 * legitimate Response with "received at X instead of Y".
 *
 * @backupStaticAttributes enabled
 */
class XForwardedPrefixTest extends \PHPUnit\Framework\TestCase
{
    /** Full ACS URL the IdP signs into @Destination. */
    private const SIGNED_DESTINATION = 'https://domain.com/portal/connect/azure/check';

    /**
     * Place $_SERVER and the Utils static state into the post-proxy
     * environment described above. Any per-test toolkit configuration
     * (setProxyVars, setBaseURL, etc.) is layered on top by the test
     * method.
     */
    private function simulateReverseProxy(): void
    {
        $_SERVER['HTTP_HOST']               = 'domain.com';
        $_SERVER['SERVER_NAME']             = 'domain.com';
        $_SERVER['SERVER_PORT']             = '80';
        $_SERVER['REQUEST_URI']             = '/connect/azure/check';
        $_SERVER['SCRIPT_NAME']             = '/connect/azure/check';
        $_SERVER['HTTP_X_FORWARDED_PROTO']  = 'https';
        $_SERVER['HTTP_X_FORWARDED_PORT']   = '443';
        $_SERVER['HTTP_X_FORWARDED_HOST']   = 'domain.com';
        $_SERVER['HTTP_X_FORWARDED_PREFIX'] = '/portal';
        unset($_SERVER['HTTPS']);
        unset($_SERVER['QUERY_STRING']);

        Utils::setSelfHost(null);
        Utils::setSelfPort(null);
        Utils::setSelfProtocol(null);
        Utils::setBaseURL(null);
        Utils::setProxyVars(false);
    }

    protected function tearDown(): void
    {
        foreach ([
            'HTTP_HOST','SERVER_NAME','SERVER_PORT','REQUEST_URI','SCRIPT_NAME',
            'HTTP_X_FORWARDED_PROTO','HTTP_X_FORWARDED_PORT','HTTP_X_FORWARDED_HOST',
            'HTTP_X_FORWARDED_PREFIX','HTTPS','QUERY_STRING',
        ] as $k) {
            unset($_SERVER[$k]);
        }
        Utils::setSelfHost(null);
        Utils::setSelfPort(null);
        Utils::setSelfProtocol(null);
        Utils::setBaseURL(null);
        Utils::setProxyVars(false);
    }

    /**
     * Baseline: with no configuration, the toolkit cannot reconstruct
     * the original URL — the prefix and the TLS scheme are both lost.
     */
    public function testBaselineMismatchWithoutAnyConfiguration(): void
    {
        $this->simulateReverseProxy();

        $this->assertSame(
            'http://domain.com/connect/azure/check',
            Utils::getSelfRoutedURLNoQuery()
        );
        $this->assertNotSame(self::SIGNED_DESTINATION, Utils::getSelfRoutedURLNoQuery());
    }

    /**
     * setProxyVars(true) recovers the scheme and port from
     * X-Forwarded-Proto / X-Forwarded-Port, but cannot recover the
     * stripped /portal prefix because the toolkit does not read
     * X-Forwarded-Prefix.
     */
    public function testProxyVarsAloneIsInsufficient(): void
    {
        $this->simulateReverseProxy();
        Utils::setProxyVars(true);

        $this->assertSame(
            'https://domain.com/connect/azure/check',
            Utils::getSelfRoutedURLNoQuery(),
            'setProxyVars(true) restores the scheme but not the stripped path prefix'
        );
        $this->assertNotSame(self::SIGNED_DESTINATION, Utils::getSelfRoutedURLNoQuery());
    }

    /**
     * Solution A
     *
     *   Utils::setProxyVars(true);
     *   Utils::setBaseURL('https://domain.com/portal/');
     *
     * Pass setBaseURL the URL *up to and including the stripped prefix*
     * (with trailing slash). setBaseURL parses it into host, port and
     * baseURLPath, and getSelfRoutedURLNoQuery then prepends the
     * baseURLPath to the (proxy-stripped) REQUEST_URI, producing the
     * full original URL that the IdP signed.
     *
     * Note: do NOT pass setBaseURL the full ACS URL, that causes the
     * known buildWithBaseURLPath doubling bug (see assertion below).
     */
    public function testFixA_SetBaseURLWithPrefixOnly(): void
    {
        $this->simulateReverseProxy();

        Utils::setProxyVars(true);
        Utils::setBaseURL('https://domain.com/portal/');

        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfRoutedURLNoQuery());
        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfURLNoQuery());
        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfURL());
    }

    /**
     * Passing the FULL ACS URL to setBaseURL doubles the
     * path because buildWithBaseURLPath appends REQUEST_URI to a
     * baseURLPath that already contains it.
     *
     * setBaseURL works if the argument is the prefix; with the full ACS URL
     * it does not work.
     */
    public function testAntiPattern_SetBaseURLWithFullAcsDoubles(): void
    {
        $this->simulateReverseProxy();

        Utils::setProxyVars(true);
        Utils::setBaseURL(self::SIGNED_DESTINATION);

        $observed = Utils::getSelfRoutedURLNoQuery();
        $this->assertNotSame(self::SIGNED_DESTINATION, $observed);
        $this->assertSame(
            'https://domain.com/portal/connect/azure/check/connect/azure/check',
            $observed,
            'Documents that setBaseURL($fullAcs) produces a doubled path'
        );
    }

    /**
     * Solution B — Recommended
     *
     *   Utils::setSelfProtocol('https');
     *   Utils::setSelfHost('domain.com');
     *   Utils::setSelfPort(443);
     *   Utils::setBaseURLPath('/portal');
     *
     * Useful when the application reads X-Forwarded-* headers itself
     * (e.g. through a framework) and wants to feed each piece to the
     * toolkit explicitly. Functionally equivalent to Fix A for the
     * destination check.
     */
    public function testFixB_GranularSettersWithBaseURLPath(): void
    {
        $this->simulateReverseProxy();

        Utils::setSelfProtocol('https');
        Utils::setSelfHost('domain.com');
        Utils::setSelfPort(443);
        Utils::setBaseURLPath('/portal');

        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfRoutedURLNoQuery());
        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfURLNoQuery());
        $this->assertSame(self::SIGNED_DESTINATION, Utils::getSelfURL());
    }

    /**
     * Integration test with Solution A applied, demonstrating that the destination check passes
     */
    public function testIntegration_ResponseDestinationValidatesUnderFixA(): void
    {
        $this->simulateReverseProxy();
        Utils::setProxyVars(true);
        Utils::setBaseURL('https://domain.com/portal/');

        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response_reverse_proxy.xml.base64');
        $settingsDir = TEST_ROOT . '/settings/';
        include $settingsDir . 'settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['sp']['assertionConsumerService']['url'] = self::SIGNED_DESTINATION;
        $settings = new Settings($settingsInfo);

        $response = new Response($settings, $message);
        $this->assertTrue($response->isValid());
    }

    /**
     * Integration test with Solution B applied, demonstrating that the destination check passes
     */
    public function testIntegration_ResponseDestinationValidatesUnderFixB(): void
    {
        $this->simulateReverseProxy();
        Utils::setProxyVars(true);
        Utils::setSelfProtocol('https');
        Utils::setSelfHost('domain.com');
        Utils::setSelfPort(443);
        Utils::setBaseURLPath('/portal');

        $message = file_get_contents(TEST_ROOT . '/data/responses/valid_response_reverse_proxy.xml.base64');
        $settingsDir = TEST_ROOT . '/settings/';
        include $settingsDir . 'settings1.php';
        $settingsInfo['strict'] = true;
        $settingsInfo['sp']['assertionConsumerService']['url'] = self::SIGNED_DESTINATION;
        $settings = new Settings($settingsInfo);

        $response = new Response($settings, $message);
        $this->assertTrue($response->isValid());
    }
}
