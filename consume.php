<?php

  error_reporting(E_ALL);

  require 'settings.php';

  require 'lib/onelogin/saml.php';

  $samlresponse = new SamlResponse(saml_get_settings(), $_POST['SAMLResponse']);

  $valid = false;

  try {
    if ($samlresponse->is_valid())
      echo "You are: ".$samlresponse->get_nameid();
    else
      echo "Invalid SAML response.";
  }
  catch e {
    echo "Invalid SAML response: " . e.getMessage();
  }

?>