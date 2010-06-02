<?php
  error_reporting(E_ALL); 
  
  require 'settings.php';

  require 'lib/onelogin/saml.php';
  
  $authrequest = new AuthRequest();
  $authrequest->user_settings = get_user_settings();
  $url = $authrequest->create();

  header("Location: $url");
?>
