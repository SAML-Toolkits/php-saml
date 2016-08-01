<?php

/**
 * SAML 2 Authentication Request
 *
 */
class OneLogin_Saml2_AuthnRequest
{

    /**
     * Object that represents the setting info
     * @var OneLogin_Saml2_Settings
     */
    protected $_settings;

    /**
     * SAML AuthNRequest string
     * @var string
     */
    private $_authnRequest;

    /**
     * SAML AuthNRequest ID.
     * @var string
     */
    private $_id;

    /**
     * Constructs the AuthnRequest object.
     *
     * @param OneLogin_Saml2_Settings $settings Settings
     * @param bool   $forceAuthn      When true the AuthNReuqest will set the ForceAuthn='true'
     * @param bool   $isPassive       When true the AuthNReuqest will set the Ispassive='true'
     * @param bool   $setNameIdPolicy When true the AuthNReuqest will set a nameIdPolicy
     */
    public function __construct(OneLogin_Saml2_Settings $settings, $forceAuthn = false, $isPassive = false, $setNameIdPolicy = true)
    {
        $this->_settings = $settings;

        $spData = $this->_settings->getSPData();
        $idpData = $this->_settings->getIdPData();
        $security = $this->_settings->getSecurityData();

        $id = OneLogin_Saml2_Utils::generateUniqueID();
        $issueInstant = OneLogin_Saml2_Utils::parseTime2SAML(time());

        $nameIdPolicyStr = '';
        if ($setNameIdPolicy) {
            $nameIDPolicyFormat = $spData['NameIDFormat'];
            if (isset($security['wantNameIdEncrypted']) && $security['wantNameIdEncrypted']) {
                $nameIDPolicyFormat = OneLogin_Saml2_Constants::NAMEID_ENCRYPTED;
            }

            $nameIdPolicyStr = <<<NAMEIDPOLICY
    <samlp:NameIDPolicy
        Format="{$nameIDPolicyFormat}"
        AllowCreate="true" />
NAMEIDPOLICY;
        }


        $providerNameStr = '';
        $organizationData = $settings->getOrganization();
        if (!empty($organizationData)) {
            $langs = array_keys($organizationData);
            if (in_array('en-US', $langs)) {
                $lang = 'en-US';
            } else {
                $lang = $langs[0];
            }
            if (isset($organizationData[$lang]['displayname']) && !empty($organizationData[$lang]['displayname'])) {
                $providerNameStr = <<<PROVIDERNAME
    ProviderName="{$organizationData[$lang]['displayname']}"
PROVIDERNAME;
            }
        }

        $forceAuthnStr = '';
        if ($forceAuthn) {
            $forceAuthnStr = <<<FORCEAUTHN

    ForceAuthn="true"
FORCEAUTHN;
        }

        $isPassiveStr = '';
        if ($isPassive) {
            $isPassiveStr = <<<ISPASSIVE

    IsPassive="true"
ISPASSIVE;
        }

        $requestedAuthnStr = '';
        if (isset($security['requestedAuthnContext']) && $security['requestedAuthnContext'] !== false) {

            $authnComparison = 'exact';
            if (isset($security['requestedAuthnContextComparison'])) {
                $authnComparison = $security['requestedAuthnContextComparison'];
            }

            if ($security['requestedAuthnContext'] === true) {
                $requestedAuthnStr = <<<REQUESTEDAUTHN
    <samlp:RequestedAuthnContext Comparison="$authnComparison">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
REQUESTEDAUTHN;
            } else {
                $requestedAuthnStr .= "    <samlp:RequestedAuthnContext Comparison=\"$authnComparison\">\n";
                foreach ($security['requestedAuthnContext'] as $contextValue) {
                    $requestedAuthnStr .= "        <saml:AuthnContextClassRef>".$contextValue."</saml:AuthnContextClassRef>\n";
                }
                $requestedAuthnStr .= '    </samlp:RequestedAuthnContext>';
            }
        }

        if (isset($idpData['idpList']) && is_array($idpData['idpList'])) {
            $idpListProxyCount = isset($idpData['idpListProxyCount']) ? $idpData['idpListProxyCount'] : 1;
            $idpListStr = '';
            foreach ($idpData['idpList'] as $idpProviderId) {
                $idpListStr .= '<samlp:IDPEntry ProviderID="' . $idpProviderId . '" />';
            }
            $scopingStr = <<<SCOPING
<samlp:Scoping ProxyCount="{$idpListProxyCount}">
    <samlp:IDPList>
        {$idpListStr}
    </samlp:IDPList>
</samlp:Scoping>
SCOPING;
        } else {
            $scopingStr = '';
        }

        if (isset($idpData['subjectNameId'])) {
            $subjectStr = <<<SUBJECT
<saml:Subject>
    <saml:NameID Format="{$nameIDPolicyFormat}">{$idpData['subjectNameId']}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>
</saml:Subject>
SUBJECT;
        } else {
            $subjectStr = '';
        }

        $request = <<<AUTHNREQUEST
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="$id"
    Version="2.0"
{$providerNameStr}{$forceAuthnStr}{$isPassiveStr}
    IssueInstant="$issueInstant"
    Destination="{$idpData['singleSignOnService']['url']}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="{$spData['assertionConsumerService']['url']}">
    <saml:Issuer>{$spData['entityId']}</saml:Issuer>
{$nameIdPolicyStr}
{$scopingStr}
{$subjectStr}
{$requestedAuthnStr}
</samlp:AuthnRequest>
AUTHNREQUEST;

        $this->_id = $id;
        $this->_authnRequest = $request;
    }

    /**
     * Returns deflated, base64 encoded, unsigned AuthnRequest.
     *
     */
    public function getRequest()
    {
        $deflatedRequest = gzdeflate($this->_authnRequest);
        $base64Request = base64_encode($deflatedRequest);
        return $base64Request;
    }

    /**
     * Returns the AuthNRequest ID.
     *
     * @return string
     */
    public function getId()
    {
        return $this->_id;
    }
}
