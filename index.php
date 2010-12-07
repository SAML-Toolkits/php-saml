<?php
  /**
   * SAMPLE Code to demonstrate how to initiate a SAML Authorization request
   *
   * When the user visits this URL, the browser will be redirected to the SSO
   * IdP with an authorization request. If successful, it will then be
   * redirected to the consume URL (specified in settings) with the auth
   * details.
   */

  error_reporting(E_ALL);

  require 'settings.php';

  require 'lib/onelogin/saml.php';

  $authrequest = new SamlAuthRequest(saml_get_settings());
  $url = $authrequest->create();

  header("Location: $url");
?>
