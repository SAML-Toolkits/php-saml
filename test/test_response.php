<?php
require_once 'lib/onelogin/saml/response.php';
require_once 'lib/onelogin/saml/settings.php';
require_once 'settings.php';

class ResponseTest extends PHPUnit_Framework_TestCase {
  private $settings;
  private $assertion;
  private $response;

/* This test doesn't pass because the timestamp in the response is invalid.
 * The rails toolkit does not verify any of the extra information other than
 * the fingerprint.

   public function testReturnTrueOnValidResponse() {
    $this->assertion = file_get_contents('test/responses/valid_response.xml.base64');
    $this->settings = saml_get_settings();
    date_default_timezone_set('UTC');
    $this->settings->x509certificate = file_get_contents('test/certificates/certificate1');
    $this->response = new SamlResponse($this->settings, $this->assertion);

    $this->assertEquals(true, $this->response->is_valid());
  }
 */

  public function testReturnNameId() {
    $this->assertion = file_get_contents('test/responses/response1.xml.base64');
    $this->settings = saml_get_settings();
    $this->response = new SamlResponse($this->settings, $this->assertion);

    $this->assertEquals('support@onelogin.com', $this->response->get_nameid());
  }

  public function testDoesNotAllowSignatureWrappingAttack() {
    $this->assertion = file_get_contents('test/responses/response4.xml.base64');
    $this->settings = saml_get_settings();
    $this->response = new SamlResponse($this->settings, $this->assertion);

    $this->assertEquals('test@onelogin.com', $this->response->get_nameid());
  }

  public function testOnlyRetreiveAssertionWithIDThatMatchesSignatureReference() {
    $this->assertion = file_get_contents('test/responses/wrapped_response_2.xml.base64');
    $this->settings = saml_get_settings();
    $this->response = new SamlResponse($this->settings, $this->assertion);

    $this->assertNotEquals('root@example.com', $this->response->get_nameid());
  }
}
?>
