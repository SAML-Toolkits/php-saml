<?php

  error_reporting(E_ALL); 

  require 'settings.php';

  require 'lib/onelogin/saml.php';

  $samlresponse = new SamlResponse($_POST['SAMLResponse']);
  $samlresponse->user_settings = get_user_settings();
  
  if ($samlresponse->is_valid())
    echo "You are: ".$samlresponse->get_nameid();
  else
    echo "Invalid SAML response.";

?>