<?php

  require(dirname(__FILE__) . '/../../xmlseclibs/xmlseclibs.php');

  class XmlSec {
    public $x509certificate;
    private $doc;
    
    function __construct($val) {
      $this->doc = $val;
    }
    
    function validateNumAssertions(){
      $rootNode = $this->doc; //->documentElement->ownerDocument;
      $assertionNodes = $rootNode->getElementsByTagName('Assertion');
      return ($assertionNodes->length == 1);
    }

    function validateTimestamps(){
      $rootNode = $this->doc;
      $timestampNodes = $rootNode->getElementsByTagName('Conditions');
      for($i=0;$i<$timestampNodes->length;$i++){
        $nbAttribute = $timestampNodes->item($i)->attributes->getNamedItem("NotBefore");
        $naAttribute = $timestampNodes->item($i)->attributes->getNamedItem("NotOnOrAfter");
        if($nbAttribute && strtotime($nbAttribute->textContent) > time()){
            return false;
        }
        if($naAttribute && strtotime($naAttribute->textContent) <= time()){
            return false;
        }
      }
      return true;
    }
 
    function is_valid() {
    	$objXMLSecDSig = new XMLSecurityDSig();

    	$objDSig = $objXMLSecDSig->locateSignature($this->doc);
    	if (! $objDSig) {
    		throw new Exception("Cannot locate Signature Node");
    	}
    	$objXMLSecDSig->canonicalizeSignedInfo();
    	$objXMLSecDSig->idKeys = array('ID');

    	$retVal = $objXMLSecDSig->validateReference();
    	if (! $retVal) {
    		throw new Exception("Reference Validation Failed");
    	}

    	$objKey = $objXMLSecDSig->locateKey();
    	if (! $objKey ) {
    		throw new Exception("We have no idea about the key");
    	}
    	$key = NULL;

    	$singleAssertion = $this->validateNumAssertions();
      if (!$singleAssertion){
        throw new Exception("Only ONE SamlAssertion allowed");
      }

      $validTimestamps = $this->validateTimestamps();
      if (!$validTimestamps){
        throw new Exception("Check your timestamp conditions");
      }

    	$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

      $objKey->loadKey($this->x509certificate, FALSE, true);
        
    	$result = $objXMLSecDSig->verify($objKey);
    	return $result;
    }

 }

?>
