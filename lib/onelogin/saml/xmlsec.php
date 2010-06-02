<?php
  require(dirname(__FILE__) . '/../../xmlseclibs/xmlseclibs.php');

  class XmlSec {
    public $x509certificate;
    private $doc;
    
    function __construct($val) {
      $this->doc = $val;
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

    	$objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

      $objKey->loadKey($this->x509certificate, FALSE, true);
      
    	$result = $objXMLSecDSig->verify($objKey);
    	return $result;
    }
  }

?>