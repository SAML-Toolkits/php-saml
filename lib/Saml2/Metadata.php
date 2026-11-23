<?php

/**
 * Metadata lib of PHP Toolkit
 *
 */

class OneLogin_Saml2_Metadata
{
    const TIME_VALID = 172800;  // 2 days
    const TIME_CACHED = 604800; // 1 week

    /**
     * Generates the metadata of the SP based on the settings
     *
     * @param array         $sp            The SP data
     * @param bool|string   $authnsign     authnRequestsSigned attribute
     * @param bool|string   $wsign         wantAssertionsSigned attribute
     * @param DateTime|null $validUntil    Metadata's valid time
     * @param int|null      $cacheDuration Duration of the cache in seconds
     * @param array         $contacts      Contacts info
     * @param array         $organization  Organization ingo
     * @param array         $attributes
     * @param bool          $ignoreValidUntil exclude the validUntil tag from metadata
     *
     * @return string SAML Metadata XML
     */
    public static function builder($sp, $authnsign = false, $wsign = false, $validUntil = null, $cacheDuration = null, $contacts = array(), $organization = array(), $attributes = array(), $ignoreValidUntil = false)
    {

        if (!isset($validUntil)) {
            $validUntil =  time() + self::TIME_VALID;
        }
        $validUntilTime =  gmdate('Y-m-d\TH:i:s\Z', $validUntil);

        if (!isset($cacheDuration)) {
            $cacheDuration = self::TIME_CACHED;
        }

        $sls = '';

        if (isset($sp['singleLogoutService'])) {
            $slsUrl = htmlspecialchars($sp['singleLogoutService']['url'], ENT_QUOTES);
            $slsBinding = htmlspecialchars($sp['singleLogoutService']['binding'], ENT_QUOTES);
            $sls = <<<SLS_TEMPLATE
        <md:SingleLogoutService Binding="{$slsBinding}"
                                Location="{$slsUrl}" />

SLS_TEMPLATE;
        }

        if ($authnsign) {
            $strAuthnsign = 'true';
        } else {
            $strAuthnsign = 'false';
        }

        if ($wsign) {
            $strWsign = 'true';
        } else {
            $strWsign = 'false';
        }

        $strOrganization = '';

        if (!empty($organization)) {
            $organizationInfoNames = array();
            $organizationInfoDisplaynames = array();
            $organizationInfoUrls = array();
            foreach ($organization as $lang => $info) {
                $lang = htmlspecialchars($lang, ENT_QUOTES);
                $orgName = htmlspecialchars($info['name'], ENT_QUOTES);
                $orgDisplayname = htmlspecialchars($info['displayname'], ENT_QUOTES);
                $orgUrl = htmlspecialchars($info['url'], ENT_QUOTES);
                $organizationInfoNames[] = <<<ORGANIZATION_NAME
       <md:OrganizationName xml:lang="{$lang}">{$orgName}</md:OrganizationName>
ORGANIZATION_NAME;
                $organizationInfoDisplaynames[] = <<<ORGANIZATION_DISPLAY
       <md:OrganizationDisplayName xml:lang="{$lang}">{$orgDisplayname}</md:OrganizationDisplayName>
ORGANIZATION_DISPLAY;
                $organizationInfoUrls[] = <<<ORGANIZATION_URL
       <md:OrganizationURL xml:lang="{$lang}">{$orgUrl}</md:OrganizationURL>
ORGANIZATION_URL;
            }
            $orgData = implode("\n", $organizationInfoNames)."\n".implode("\n", $organizationInfoDisplaynames)."\n".implode("\n", $organizationInfoUrls);
            $strOrganization = <<<ORGANIZATIONSTR

    <md:Organization>
{$orgData}
    </md:Organization>
ORGANIZATIONSTR;
        }

        $strContacts = '';
        if (!empty($contacts)) {
            $contactsInfo = array();
            foreach ($contacts as $type => $info) {
                $type = htmlspecialchars($type, ENT_QUOTES);
                $givenName = htmlspecialchars($info['givenName'], ENT_QUOTES);
                $emailAddress = htmlspecialchars($info['emailAddress'], ENT_QUOTES);
                $contactsInfo[] = <<<CONTACT
    <md:ContactPerson contactType="{$type}">
        <md:GivenName>{$givenName}</md:GivenName>
        <md:EmailAddress>{$emailAddress}</md:EmailAddress>
    </md:ContactPerson>
CONTACT;
            }
            $strContacts = "\n".implode("\n", $contactsInfo);
        }

        $strAttributeConsumingService = '';
        if (isset($sp['attributeConsumingService'])) {
            $attrCsDesc = '';
            if (isset($sp['attributeConsumingService']['serviceDescription'])) {
                $attrCsDesc = sprintf(
                    '            <md:ServiceDescription xml:lang="en">%s</md:ServiceDescription>' . PHP_EOL,
                    htmlspecialchars($sp['attributeConsumingService']['serviceDescription'], ENT_QUOTES)
                );
            }
            if (!isset($sp['attributeConsumingService']['serviceName'])) {
                $sp['attributeConsumingService']['serviceName'] = 'Service';
            }
            $requestedAttributeData = array();
            foreach ($sp['attributeConsumingService']['requestedAttributes'] as $attribute) {
                $requestedAttributeStr = sprintf('            <md:RequestedAttribute Name="%s"', htmlspecialchars($attribute['name'], ENT_QUOTES));
                if (isset($attribute['nameFormat'])) {
                    $requestedAttributeStr .= sprintf(' NameFormat="%s"', htmlspecialchars($attribute['nameFormat'], ENT_QUOTES));
                }
                if (isset($attribute['friendlyName'])) {
                    $requestedAttributeStr .= sprintf(' FriendlyName="%s"', htmlspecialchars($attribute['friendlyName'], ENT_QUOTES));
                }
                if (isset($attribute['isRequired'])) {
                    $requestedAttributeStr .= sprintf(' isRequired="%s"', $attribute['isRequired'] === true ? 'true' : 'false');
                }
                $reqAttrAuxStr = " />";

                if (isset($attribute['attributeValue']) && !empty($attribute['attributeValue'])) {
                    $reqAttrAuxStr = '>';
                    if (is_string($attribute['attributeValue'])) {
                        $attribute['attributeValue'] = array($attribute['attributeValue']);
                    }
                    foreach ($attribute['attributeValue'] as $attrValue) {
                        $attrValue = htmlspecialchars($attrValue, ENT_QUOTES);
                        $reqAttrAuxStr .=<<<ATTRIBUTEVALUE

                <saml:AttributeValue xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{$attrValue}</saml:AttributeValue>
ATTRIBUTEVALUE;
                    }
                    $reqAttrAuxStr .= "\n            </md:RequestedAttribute>";
                }

                $requestedAttributeData[] = $requestedAttributeStr . $reqAttrAuxStr;
            }

            $requestedAttributeStr = implode(PHP_EOL, $requestedAttributeData);
            $serviceName = htmlspecialchars($sp['attributeConsumingService']['serviceName'], ENT_QUOTES);
            $strAttributeConsumingService = <<<METADATA_TEMPLATE

        <md:AttributeConsumingService index="1">
            <md:ServiceName xml:lang="en">{$serviceName}</md:ServiceName>
{$attrCsDesc}{$requestedAttributeStr}
        </md:AttributeConsumingService>
METADATA_TEMPLATE;
        }

        if ($ignoreValidUntil) {
            $timeStr = <<<TIME_TEMPLATE
cacheDuration="PT{$cacheDuration}S"
TIME_TEMPLATE;
        } else {
            $timeStr = <<<TIME_TEMPLATE
validUntil="{$validUntilTime}"
                     cacheDuration="PT{$cacheDuration}S"
TIME_TEMPLATE;
        }

        $spEntityId = htmlspecialchars($sp['entityId'], ENT_QUOTES);
        $acsUrl = htmlspecialchars($sp['assertionConsumerService']['url'], ENT_QUOTES);
        $acsBinding = htmlspecialchars($sp['assertionConsumerService']['binding'], ENT_QUOTES);
        $nameIdFormat = htmlspecialchars($sp['NameIDFormat'], ENT_QUOTES);
        $metadata = <<<METADATA_TEMPLATE
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                     {$timeStr}
                     entityID="{$spEntityId}">
    <md:SPSSODescriptor AuthnRequestsSigned="{$strAuthnsign}" WantAssertionsSigned="{$strWsign}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
{$sls}        <md:NameIDFormat>{$nameIdFormat}</md:NameIDFormat>
        <md:AssertionConsumerService Binding="{$acsBinding}"
                                     Location="{$acsUrl}"
                                     index="1" />{$strAttributeConsumingService}
    </md:SPSSODescriptor>{$strOrganization}{$strContacts}
</md:EntityDescriptor>
METADATA_TEMPLATE;
        return $metadata;
    }

    /**
     * Signs the metadata with the key/cert provided
     *
     * @param string $metadata SAML Metadata XML
     * @param string $key x509 key
     * @param string $cert x509 cert
     * @param string $signAlgorithm Signature algorithm method
     * @param string $digestAlgorithm Digest algorithm method
     *
     * @return string Signed Metadata
     *
     * @throws Exception
     */
    public static function signMetadata($metadata, $key, $cert, $signAlgorithm = XMLSecurityKey::RSA_SHA1, $digestAlgorithm = XMLSecurityDSig::SHA1)
    {
        return OneLogin_Saml2_Utils::addSign($metadata, $key, $cert, $signAlgorithm, $digestAlgorithm);
    }

    /**
     * Adds the x509 descriptors (sign/encriptation) to the metadata
     * The same cert will be used for sign/encrypt
     *
     * @param string $metadata SAML Metadata XML
     * @param string $cert x509 cert
     * @param bool $wantsEncrypted Whether to include the KeyDescriptor for encryption
     *
     * @return string Metadata with KeyDescriptors
     *
     * @throws Exception
     */
    public static function addX509KeyDescriptors($metadata, $cert, $wantsEncrypted = true)
    {
        $xml = new DOMDocument();
        $xml->preserveWhiteSpace = false;
        $xml->formatOutput = true;
        try {
            $xml = OneLogin_Saml2_Utils::loadXML($xml, $metadata);
            if (!$xml) {
                throw new Exception('Error parsing metadata');
            }
        } catch (Exception $e) {
            throw new Exception('Error parsing metadata. '.$e->getMessage());
        }

        $formatedCert = OneLogin_Saml2_Utils::formatCert($cert, false);
        $x509Certificate = $xml->createElementNS(OneLogin_Saml2_Constants::NS_DS, 'X509Certificate', $formatedCert);

        $keyData = $xml->createElementNS(OneLogin_Saml2_Constants::NS_DS, 'ds:X509Data');
        $keyData->appendChild($x509Certificate);

        $keyInfo = $xml->createElementNS(OneLogin_Saml2_Constants::NS_DS, 'ds:KeyInfo');
        $keyInfo->appendChild($keyData);

        $keyDescriptor = $xml->createElementNS(OneLogin_Saml2_Constants::NS_MD, "md:KeyDescriptor");

        $SPSSODescriptor = $xml->getElementsByTagName('SPSSODescriptor')->item(0);
        $SPSSODescriptor->insertBefore($keyDescriptor->cloneNode(), $SPSSODescriptor->firstChild);
        if ($wantsEncrypted === true) {
            $SPSSODescriptor->insertBefore($keyDescriptor->cloneNode(), $SPSSODescriptor->firstChild);
        }

        $signing = $xml->getElementsByTagName('KeyDescriptor')->item(0);
        $signing->setAttribute('use', 'signing');
        $signing->appendChild($keyInfo);

        if ($wantsEncrypted === true) {
            $encryption = $xml->getElementsByTagName('KeyDescriptor')->item(1);
            $encryption->setAttribute('use', 'encryption');

            $encryption->appendChild($keyInfo->cloneNode(true));
        }

        return $xml->saveXML();
    }
}
