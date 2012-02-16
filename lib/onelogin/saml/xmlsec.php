<?php

require(dirname(__FILE__) . '/../../xmlseclibs/xmlseclibs.php');

/**
 * Determine if the SAML response is valid using a provided x509 certificate.
 */
class SamlXmlSec {
    /**
     * A SamlResponse class provided to the constructor.
     */
    private $settings;

    /**
     * The documentument to be tested.
     */
    private $document;

    /**
     * Construct the SamlXmlSec object.
     *
     * @param SamlResponse $settings
     *   A SamlResponse settings object containing the necessary
     *   x509 certicate to test the document.
     * @param string $document
     *   The document to test.
     */
    public function __construct($settings, $document) {
        $this->settings = $settings;
        $this->document = $document;
    }


    /**
     * Determine if the document passes the security test.
     *
     * @return
     *   TRUE if the document passes. This could throw a generic Exception
     *   if the document or key cannot be found.
     */
    public function validateNumAssertions(){
        $rootNode = $this->document; //->documentElement->ownerDocument;
        $assertionNodes = $rootNode->getElementsByTagName('Assertion');
        return ($assertionNodes->length == 1);
    }

    public function validateTimestamps(){
        $rootNode = $this->document;
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

    public function is_valid() {
        $objXMLSecDSig = new XMLSecurityDSig();

        $objDSig = $objXMLSecDSig->locateSignature($this->document);
        if(! $objDSig) {
            throw new Exception("Cannot locate Signature Node");
        }
        $objXMLSecDSig->canonicalizeSignedInfo();
        $objXMLSecDSig->idKeys = array('ID');

        $retVal = $objXMLSecDSig->validateReference();
        if(! $retVal) {
            throw new Exception("Reference Validation Failed");
        }

        $objKey = $objXMLSecDSig->locateKey();
        if(! $objKey ) {
            throw new Exception("We have no idea about the key");
        }
        $key = null;

        $singleAssertion = $this->validateNumAssertions();
        if(!$singleAssertion){
            throw new Exception("Only one SAMLAssertion allowed");
        }

        $validTimestamps = $this->validateTimestamps();
        if (!$validTimestamps){
            throw new Exception("SAMLAssertion conditions not met");
        }

        $objKeyInfo = XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        $objKey->loadKey($this->settings->x509certificate, false, true);

        $result = $objXMLSecDSig->verify($objKey);
        return $result;
    }
}
