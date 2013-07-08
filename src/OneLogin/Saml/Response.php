<?php

/**
 * Parse the SAML response and maintain the XML for it.
 */
class OneLogin_Saml_Response
{
    /**
     * @var OneLogin_Saml_Settings
     */
    protected $_settings;

    /**
     * The decoded, unprocessed XML message provided to the constructor.
     * @var string
     */
    protected $assertion;
    
    /**
     * The path of assertion node. It is lazy-initilized in the _findAssertion()
     * method to speedup queries.
     * @var string 
     */
    private $assertionPath;

    /**
     * The assertion was encrypted in the response.
     */
    public $encrypted = FALSE;

    /**
     * A DOMDocument class loaded from the $assertion.
     * @var DomDocument
     */
    public $document;

    /**
     * Construct the response object.
     *
     * Raises exception for basic malformed/incomplete response.
     * 
     * According Interoperable SAML 2.0 Web Browser SSO Deployment Profile,
     * par. 9.2, the response MUST contain exactly one assertion (encrypted or
     * not).
     * 
     * @param OneLogin_Saml_Settings $settings Settings containing the necessary X.509 certificate to decode the XML.
     * @param string $assertion A UUEncoded SAML assertion from the IdP.
     */
    public function __construct(OneLogin_Saml_Settings $settings, $assertion)
    {
        $this->_settings = $settings;
        $this->assertion = base64_decode($assertion);
        $this->document = new DOMDocument();
        $this->document->loadXML($this->assertion);

        // Check SAML version
        if ($this->document->documentElement->getAttribute('Version') != '2.0') {
            throw new Exception('Unsupported SAML version');
        }

        // Quick check for the presence of EncryptedAssertion
        $encryptedAssertionNodes = $this->document->getElementsByTagName('EncryptedAssertion');
        if ($encryptedAssertionNodes->length > 1) {
            throw new Exception('Multiple encrypted assertions are not supported');
        }
        else if ($encryptedAssertionNodes->length == 1) {
            // Decrypt
            $this->encrypted = TRUE;
            $this->_decryptAssertion($this->document);
        }
    }

    /**
     * Determine if the SAML Response is valid using the certificate.
     *
     * @throws Exception
     * @return bool Validate the document
     */
    public function isValid()
    {
        $xmlSec = new OneLogin_Saml_XmlSec($this->_settings, $this);
        return $xmlSec->isValid();
    }

    /**
     * Get the URI reference indicating the address to which the response has
     * been sent or NULL if not address id specified.
     * If present, the receiver must check it if equals to the spReturnUrl
     * See SAML core spec. par. 3.2.2.
     */
    public function getDestination()
    {
        $destination = $this->document->documentElement->getAttribute('Destination');
        return empty($destination) ? NULL : $destination;
    }
    
    /**
     * Get the NameID provided by the SAML response from the IdP.
     */
    public function getNameId()
    {
        $entries = $this->_queryAssertion('/saml:Subject/saml:NameID');
        return $entries->item(0)->nodeValue;
    }

    /**
     * Get the SessionNotOnOrAfter attribute, as Unix Epoch, from the
     * AuthnStatement element.
     * Using this attribute, the IdP suggests the local session expiration
     * time.
     * 
     * @return The SessionNotOnOrAfter as unix epoc or NULL if not present
     */
    public function getSessionNotOnOrAfter()
    {
        $entries = $this->_queryAssertion('/saml:AuthnStatement[@SessionNotOnOrAfter]');
        if ($entries->length == 0) {
            return NULL;
        }
        $notOnOrAfter = $entries->item(0)->getAttribute('SessionNotOnOrAfter');
        return strtotime($notOnOrAfter);
    }

    public function getAttributes()
    {
        $entries = $this->_queryAssertion('/saml:AttributeStatement/saml:Attribute');

        $attributes = array();
        /** @var $entry DOMNode */
        foreach ($entries as $entry) {
            $attributeName = $entry->attributes->getNamedItem('Name')->nodeValue;

            $attributeValues = array();
            $children = $entry->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'AttributeValue');
            foreach ($children as $childNode) {
                $attributeValues[] = $childNode->nodeValue;
            }

            $attributes[$attributeName] = $attributeValues;
        }
        return $attributes;
    }

    /**
     * Search the assertion node and validate the signature.
     * Signature is validated only once.
     */
    protected function _findAssertion() {
        if (!empty($this->assertionPath)) {
            return $this->assertionPath;
        }
        
        $xpath = new DOMXPath($this->document);
        $xpath->registerNamespace('samlp'   , 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml'    , 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds'      , 'http://www.w3.org/2000/09/xmldsig#');

        $assertionNode = $this->encrypted ? '/samlp:Response/saml:EncryptedAssertion/saml:Assertion'
                : '/samlp:Response/saml:Assertion';
        $signatureQuery = $assertionNode . '/ds:Signature/ds:SignedInfo/ds:Reference';
        $assertionReferenceNode = $xpath->query($signatureQuery)->item(0);
        if (!$assertionReferenceNode) {
            // is the response signed as a whole?
            if ($this->encrypted) {
                throw new Exception('Signed Response with encrypted assertion not supported yet');	
            }
            $signatureQuery = '/samlp:Response/ds:Signature/ds:SignedInfo/ds:Reference';
            $assertionReferenceNode = $xpath->query($signatureQuery)->item(0);
            if (!$assertionReferenceNode) {
                throw new Exception('Unable to query assertion or response, no Signature Reference found?');	
            }
            $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);

            $this->assertionPath = "/samlp:Response[@ID='$id']/saml:Assertion";
        } else {
            $id = substr($assertionReferenceNode->attributes->getNamedItem('URI')->nodeValue, 1);

            $this->assertionPath = "{$assertionNode}[@ID='$id']";
        }
        
        return $this->assertionPath;
    }
    
    /**
     * @param string $assertionXpath
     * @return DOMNodeList
     */
    protected function _queryAssertion($assertionXpath)
    {
        $xpath = new DOMXPath($this->document);
        $xpath->registerNamespace('samlp'   , 'urn:oasis:names:tc:SAML:2.0:protocol');
        $xpath->registerNamespace('saml'    , 'urn:oasis:names:tc:SAML:2.0:assertion');
        $xpath->registerNamespace('ds'      , 'http://www.w3.org/2000/09/xmldsig#');

        $nameQuery = $this->_findAssertion() . $assertionXpath;
        return $xpath->query($nameQuery);
    }
    
    /**
     * Decrypt an EncryptedAssertion and replace in the DOM the node content
     * with the cleartext Assertion.
     * 
     * @throws Exception
     */
    private function _decryptAssertion($dom) {
        if (empty($this->_settings->spPrivateKey)) 
        {
            throw new Exception("No private key available, check settings");
        }
        
        $objenc = new XMLSecEnc();
        $encData = $objenc->locateEncryptedData($dom);
        if (!$encData)
        {
            throw new Exception("Cannot locate encrypted assertion");
        }
        
        $objenc->setNode($encData);
        $objenc->type = $encData->getAttribute("Type");
        if (!$objKey = $objenc->locateKey())
        {
            throw new Exception("Unknown algorithm");
        }

        $key = NULL;
        if ($objKeyInfo = $objenc->locateKeyInfo($objKey)) {
            if ($objKeyInfo->isEncrypted) {
                $objencKey = $objKeyInfo->encryptedCtx;
                $objKeyInfo->loadKey($this->_settings->spPrivateKey, FALSE, FALSE);
                $key = $objencKey->decryptKey($objKeyInfo);
            }
        }
                
        if (empty($objKey->key)) {
            $objKey->loadKey($key);
        }
       
        $decrypt = $objenc->decryptNode($objKey, TRUE);
        if ($decrypt instanceof DOMDocument)
        {	
            $this->document = $decrypt;
        } else {
            $this->document = $decrypt->ownerDocument;
        }           
        
    }
    
}
