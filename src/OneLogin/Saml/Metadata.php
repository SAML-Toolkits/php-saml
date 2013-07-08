<?php

/**
 * Create SAML2 Metadata documents
 */
class OneLogin_Saml_Metadata
{
    /**
     * How long should the metadata be valid?
     */
    const VALIDITY_SECONDS = 604800; // 1 week

    /**
     * Service settings
     * @var OneLogin_Saml_Settings
     */
    protected $_settings;

    /**
     * Create a new Metadata document
     * @param OneLogin_Saml_Settings $settings
     */
    public function __construct(OneLogin_Saml_Settings $settings)
    {
        $this->_settings = $settings;
    }

    /**
     * @return string
     */
    public function getXml()
    {
        $validUntil = $this->_getMetadataValidTimestamp();

        $certificate = '';
        if (!empty($this->_settings->spPublicCertificate))
        {
            if (empty($this->_settings->spPrivateKey))
            {
                throw new Exception('A SP certificate is useless without the private key');
            }
                $x509cert = str_replace(array('-----BEGIN CERTIFICATE-----',
                    '-----END CERTIFICATE-----',
                    "\r", "\n", " ", "\t"), '', $this->_settings->spPublicCertificate);
                $certData = chunk_split($x509cert, 64, "\n");
                $certificate = <<<TEMPLATE
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>
$certData                    </ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
            <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
        </md:KeyDescriptor>
        
TEMPLATE;
        }
        
        return <<<METADATA_TEMPLATE
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     validUntil="$validUntil"
                     entityID="{$this->_settings->spIssuer}">
    <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        {$certificate}<md:NameIDFormat>{$this->_settings->requestedNameIdFormat}</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="{$this->_settings->spReturnUrl}"
                                     index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>
METADATA_TEMPLATE;
    }

    protected function _getMetadataValidTimestamp()
    {
        $timeZone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        $time = strftime("%Y-%m-%dT%H:%M:%SZ", time() + self::VALIDITY_SECONDS);
        date_default_timezone_set($timeZone);
        return $time;
    }
}