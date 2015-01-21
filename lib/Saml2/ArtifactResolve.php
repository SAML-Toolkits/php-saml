<?php
/**
 * SAML 2 Artifact Resolve Request
 */
class OneLogin_Saml2_ArtifactResolve
{
    /**
     * @var string
     */
    protected $_id;

    /**
     * @var string
     */
    protected $_request;

    /**
     * Tag after which to insert the signature
     * @var DOMElement
     */
    protected $_signatureBefore;

    /**
     * @var DOMDocument
     */
    protected $_document;

    /**
     * @var DOMElement
     */
    protected $_root;

    /**
     * @var OneLogin_Saml2_Settings
     */
    protected $_settings;

    /**
     * Constructs the SAML Response object.
     *
     * @param OneLogin_Saml2_Settings $settings Settings.
     * @param string $destination
     * @param string $artifact
     * @throws OneLogin_Saml2_Error
     */
    public function __construct(OneLogin_Saml2_Settings $settings, $destination, $artifact)
    {
        $this->_settings = $settings;
        $spData = $settings->getSPData();

        $this->_document = $document = new DOMDocument();
        $this->_root = $root = $document->createElementNS(OneLogin_Saml2_Constants::NS_SAMLP, 'samlp:ArtifactResolve');
        $document->appendChild($root);

        // Root attributes
        $id = OneLogin_Saml2_Utils::generateUniqueID();
        $issueInstant = OneLogin_Saml2_Utils::parseTime2SAML(time());
        $root->setAttribute('ID', $id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', $issueInstant);
        $root->setAttribute('Destination', $destination);

        // Add the issuer
        $issuer = $document->createElementNS(OneLogin_Saml2_Constants::NS_SAML, 'saml:Issuer', $spData['entityId']);
        $root->appendChild($issuer);

        // Add the artifact
        $artifactTag = $document->createElementNS(OneLogin_Saml2_Constants::NS_SAMLP, 'samlp:Artifact', $artifact);
        $this->_signatureBefore = $artifactTag;
        $root->appendChild($artifactTag);
    }

    /**
     * Creates signed XML message.
     *
     * Credits for most of this function go to the SimpleSAMLphp Library.
     * @param bool $root Return the root element rather than the whole document.
     * @return string
     * @throws Exception
     */
    public function getXML($root = false) {
        $settings = $this->_settings;
        if (!($privateKey = $settings->getSPKey())) {
            // No key, do not sign the message
            return $this->_document->saveXML();
        }

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
        $key->loadKey($privateKey);
        $xmlSig = new XMLSecurityDSig();
        $xmlSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

        switch ($key->type) {
            case XMLSecurityKey::RSA_SHA256:
                $type = XMLSecurityDSig::SHA256;
                break;
            case XMLSecurityKey::RSA_SHA384:
                $type = XMLSecurityDSig::SHA384;
                break;
            case XMLSecurityKey::RSA_SHA512:
                $type = XMLSecurityDSig::SHA512;
                break;
            default:
                $type = XMLSecurityDSig::SHA1;
        }

        $xmlSig->addReferenceList(array($this->_root), $type,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID', 'overwrite' => FALSE)
        );

        $xmlSig->sign($key);

        if ($cert = $settings->getSPcert()) {
            $xmlSig->add509Cert($cert, true);
        }

        $xmlSig->insertSignature($this->_root, $this->_signatureBefore);
        return $this->_document->saveXML($root ? $this->_root : null);
    }
}