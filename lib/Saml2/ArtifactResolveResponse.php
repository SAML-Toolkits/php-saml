<?php
/**
 * SAML 2 Artifact Resolve Request
 */
class OneLogin_Saml2_ArtifactResolveResponse
{
    /**
     * @var bool
     */
    protected $_isValid = false;

    /**
     * @var string
     */
    protected $_statusCode = null;

    /**
     * Constructs the SAML Response object.
     *
     * @param OneLogin_Saml2_Settings $settings Settings.
     * @param string $response SOAP XML response
     * @throws OneLogin_Saml2_Error
     */
    public function __construct(OneLogin_Saml2_Settings $settings, $response)
    {
        $document = new DOMDocument();
        if (!($document = OneLogin_Saml2_Utils::loadXML($document, $response))) {
            return;
        }

        $xpath = new DOMXPath($document);
        $xpath->registerNamespace('protocol', OneLogin_Saml2_Constants::NS_SAMLP);
        $xpath->registerNamespace('assertion', OneLogin_Saml2_Constants::NS_SAML);

        $idpData = $settings->getIdPData();
        $issuer = $this->_extract($xpath, '//assertion:Issuer');
        if ($idpData['entityId'] !== $issuer) {
            throw new OneLogin_Saml2_Error(
                'Issuer mismatch',
                OneLogin_Saml2_Error::SAML_ISSUER_MISMATCH
            );
        }

        $this->_statusCode = $this->_extract($xpath, '//protocol:Status/protocol:StatusCode/@Value');

        // TODO Process the assertion
    }

    /**
     * @param DOMXPath $xpath
     * @param string $query
     * @return null|string
     */
    protected function _extract($xpath, $query) {
        $v = $xpath->query($query);
        return $v->length > 0 ? $v->item(0)->nodeValue : null;
    }

    /**
     * @return bool
     */
    public function isSuccessful() {
        return $this->_statusCode === OneLogin_Saml2_Constants::STATUS_SUCCESS;
    }

    /**
     * @return DOMNodeList|string
     */
    public function getStatusCode() {
        return $this->_statusCode;
    }
}