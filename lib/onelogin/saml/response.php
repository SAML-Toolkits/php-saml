<?php
  require 'xmlsec.php';

  class SamlResponse {
    private $nameid;
    private $xml;
    private $xpath;
    
    public $user_settings;
    
    function __construct($val) {
      // $this->xml = new SimpleXMLElement(base64_decode($val));
      $this->xml = new DOMDocument();

      $this->xml->loadXML(base64_decode($val));
    }
    
    function is_valid() {
      $xmlsec = new XmlSec($this->xml);
      $xmlsec->x509certificate = $this->user_settings->x509certificate;
      return $xmlsec->is_valid();
    }
    
    function get_nameid() {
      $xpath = new DOMXPath($this->xml);
      $query = "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID";
      
      $entries = $xpath->query($query);
      return $entries->item(0)->nodeValue;
    }
  }

?>
