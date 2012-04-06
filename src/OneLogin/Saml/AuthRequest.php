<?php

/**
 * Create a SAML authorization request.
 */
class OneLogin_Saml_AuthRequest
{
    const ID_PREFIX = 'ONELOGIN';

    /**
     * A SamlResponse class provided to the constructor.
     * @var OneLogin_Saml_Settings
     */
    private $_settings;

    /**
     * Construct the response object.
     *
     * @param OneLogin_Saml_Settings $settings
     *   A SamlResponse settings object containing the necessary
     *   x509 certicate to decode the XML.
     */
    public function __construct(OneLogin_Saml_Settings $settings)
    {
        $this->_settings = $settings;
    }

    /**
     * Generate the request.
     *
     * @return string A fully qualified URL that can be redirected to in order to process the authorization request.
     */
    public function getRedirectUrl()
    {
        $id = $this->_generateUniqueID();
        $issueInstant = $this->_getTimestamp();

        $request = <<<AUTHNREQUEST
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
       ID="$id" 
       Version="2.0" 
       IssueInstant="$issueInstant"
       ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
       AssertionConsumerServiceURL="{$this->_settings->spReturnUrl}">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{$this->_settings->spIssuer}</saml:Issuer>
    <samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        Format="{$this->_settings->requestedNameIdFormat}"
                        AllowCreate="true"></samlp:NameIDPolicy>
    <samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact">
        <saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            >urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>
</samlp:AuthnRequest>";
AUTHNREQUEST;

        $deflatedRequest = gzdeflate($request);
        $base64Request = base64_encode($deflatedRequest);
        $encodedRequest = urlencode($base64Request);

        return $this->_settings->idpSingleSignOnUrl . "?SAMLRequest=" . $encodedRequest;
    }

    private function _generateUniqueID()
    {
        return self::ID_PREFIX . sha1(uniqid(mt_rand(), TRUE));
    }

    private function _getTimestamp()
    {
        $defaultTimezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        $timestamp = strftime("%Y-%m-%dT%H:%M:%SZ");
        date_default_timezone_set($defaultTimezone);
        return $timestamp;
    }
}