<?php
  class authrequest {
    public $user_settings;

    public function create() {
      $id                = $this->generateUniqueID(20);
      $issue_instant     = $this->getTimestamp();

      global $const_assertion_consumer_service_url;
      global $const_issuer;
      global $const_name_identifier_format;
      $request =
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"$id\" Version=\"2.0\" IssueInstant=\"$issue_instant\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"".$const_assertion_consumer_service_url."\">".
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">".$const_issuer."</saml:Issuer>\n".
        "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"".$const_name_identifier_format."\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n".
        "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">".
        "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n".
        "</samlp:AuthnRequest>";

      $deflated_request  = gzdeflate($request);
      $base64_request    = base64_encode($deflated_request);
      $encoded_request   = urlencode($base64_request);

      return $this->user_settings->idp_sso_target_url."?SAMLRequest=".$encoded_request;
    }

    private function generateUniqueID($length) {
      $chars = "abcdef0123456789";
      $chars_len = strlen($chars);
      $uniqueID = "";
      for ($i = 0; $i < $length; $i++)
        $uniqueID .= substr($chars,rand(0,15),1);
      return "_".$uniqueID;
    }

    private function getTimestamp() {
      date_default_timezone_set('UTC');
      return strftime("%Y-%m-%dT%H:%M:%SZ");
    }
  };
?>