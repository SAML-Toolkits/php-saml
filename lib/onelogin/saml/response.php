<?php
  require 'xmlsec.php';

  /**
   * Parse the SAML response and maintain the XML for it.
   */
  class SamlResponse {
    /**
     * A SamlResponse class provided to the constructor.
     */
    private $settings;

    /**
     * The decoded, unprocessed XML assertion provided to the constructor.
     */
    public $assertion;

    /**
     * A DOMDocument class loaded from the $assertion.
     */
    public $xml;

    // At this time these private members are unused.
    private $nameid;
    private $xpath;

    /**
     * Construct the response object.
     *
     * @param SamlResponse $settings
     *   A SamlResponse settings object containing the necessary
     *   x509 certicate to decode the XML.
     * @param string $assertion
     *   A UUEncoded SAML assertion from the IdP.
     */
    function __construct($settings, $assertion) {
      $this->settings = $settings;
      $this->assertion = base64_decode($assertion);
      $this->xml = new DOMDocument();
      $this->xml->loadXML($this->assertion);
    }

    /**
     * Determine if the SAML Response is valid using the certificate.
     */
    function is_valid() {
      $xmlsec = new XmlSec($this->xml);
      $xmlsec->x509certificate = $this->settings->x509certificate;
      return $xmlsec->is_valid();
    }

    /**
     * Get the NameID provided by the SAML response from the IdP.
     */
    function get_nameid() {
      $xpath = new DOMXPath($this->xml);
      $query = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";

      $entries = $xpath->query($query);
      return $entries->item(0)->nodeValue;
    }
  }

?>
