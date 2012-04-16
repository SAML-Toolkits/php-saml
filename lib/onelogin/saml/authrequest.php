<?php
  /**
   * Create a SAML authorization request.
   */
  class SamlAuthRequest {
    /**
     * A SamlResponse class provided to the constructor.
     */
    private $settings;

    /**
     * Construct the response object.
     *
     * @param SamlResponse $settings
     *   A SamlResponse settings object containing the necessary
     *   x509 certicate to decode the XML.
     */
    function __construct($settings) {
      $this->settings = $settings;
    }

    /**
     * Generate the request.
     *
     * @return
     *   A fully qualified URL that can be redirected to in order to process
     *   the authorization request.
     */
    public function create() {
      $id                = $this->generateUniqueID(20);
      $issue_instant     = $this->getTimestamp();

      $request =
        "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"$id\" Version=\"2.0\" IssueInstant=\"$issue_instant\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"".$this->settings->assertion_consumer_service_url."\">".
        "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">".$this->settings->issuer."</saml:Issuer>\n".
        "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"".$this->settings->name_identifier_format."\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n".
        "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">".
        "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n".
        "</samlp:AuthnRequest>";

      $deflated_request  = gzdeflate($request);
      $base64_request    = base64_encode($deflated_request);
      $encoded_request   = urlencode($base64_request);

      return $this->settings->idp_sso_target_url."?SAMLRequest=".$encoded_request;
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