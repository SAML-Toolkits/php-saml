<?php
require_once('Settings.php');
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
    protected $_settings;

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
<samlp:AuthnRequest 
	xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
	xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
	Version="2.0" 
	ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
	<saml:Issuer />
	<samlp:NameIDPolicy AllowCreate="true"/>
	<samlp:RequestedAuthnContext Comparison="exact">
		<saml:AuthnContextClassRef>
		urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
		</saml:AuthnContextClassRef>
	</samlp:RequestedAuthnContext>
</samlp:AuthnRequest>
AUTHNREQUEST;

        $auth_req = new SimpleXMLElement($request);
        $req_ns = $auth_req->getNameSpaces(true);
        $samlp = $auth_req->children($req_ns['samlp']);
        $saml = $auth_req->children($req_ns['saml']);

        $auth_req->addAttribute('ID', $id);
        $auth_req->addAttribute('IssueInstant', $issueInstant);
        $auth_req->addAttribute('AssertionConsumerServiceURL', $this->_settings->spReturnUrl);
        $auth_req->Issuer = $this->_settings->spIssuer;
        $samlp->NameIDPolicy->addAttribute('Format', $this->_settings->requestedNameIdFormat);
        $request = $auth_req->asXML();

        $deflatedRequest = gzdeflate($request);
        $base64Request = base64_encode($deflatedRequest);
        $encodedRequest = urlencode($base64Request);

        return $this->_settings->idpSingleSignOnUrl . "?SAMLRequest=" . $encodedRequest;
    }

    protected function _generateUniqueID()
    {
        return self::ID_PREFIX . sha1(uniqid(mt_rand(), TRUE));
    }

    protected function _getTimestamp()
    {
        $defaultTimezone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        $timestamp = strftime("%Y-%m-%dT%H:%M:%SZ");
        date_default_timezone_set($defaultTimezone);
        return $timestamp;
    }
}
