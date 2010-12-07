<?php
  error_reporting(E_ALL);

  require 'settings.php';

  require 'lib/onelogin/saml.php';

  $authrequest = new SamlAuthRequest(saml_get_settings());
  $url = $authrequest->create();

  header("Location: $url");
?>
