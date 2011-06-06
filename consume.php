<?php
  /**
   * SAMPLE Code to demonstrate how to handle a SAML assertion response.
   *
   * The URL of this file will have been given during the SAML authorization.
   * After a successful authorization, the browser will be directed to this
   * link where it will send a certified response via $_POST.
   */

  error_reporting(E_ALL);

  require 'settings.php';

  require 'lib/onelogin/saml.php';

  $samlresponse = new SamlResponse(saml_get_settings(), $_POST['SAMLResponse']);

  try {
    if ($samlresponse->is_valid())
      echo "You are: ".$samlresponse->get_nameid();
    else
      echo "Invalid SAML response.";
  }
  catch (Exception $e) {
    echo "Invalid SAML response: " . $e->getMessage();
  }

?>