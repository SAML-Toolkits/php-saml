<?php

/**
 * Main class of OneLogin's PHP Toolkit
 *
 */
class OneLogin_Saml2_Auth
{

    /**
     * Settings data.
     *
     * @var array
     */
    private $_settings;

    /**
     * User attributes data.
     *
     * @var array
     */
    private $_attributes = array();

    /**
     * NameID
     *
     * @var string
     */
    private $_nameid;

    /**
     * If user is authenticated.
     *
     * @var boolean
     */
    private $_authenticated = false;

    /**
     * If any error.
     *
     * @var array
     */
    private $_errors = array();

    /**
     * Initializes the SP SAML instance.
     *
     * @param array $oldSettings Setting data
     */
    public function __construct($oldSettings = null)
    {
        $this->_settings = new OneLogin_Saml2_Settings($oldSettings);
    }

    /**
     * Returns the settings info
     *
     * @return array  The settings data.
     */
    public function getSettings()
    {
        return $this->_settings;
    }

    /**
     * Set the strict mode active/disable
     *
     * @param boolean $value Strict parameter
     *
     * @return array The settings data.
     */
    public function setStrict($value)
    {
        assert('is_bool($value)');
        $this->_settings->setStrict($value);
    }

    /**
     * Process the SAML Response sent by the IdP.
     *
     * @param string $requestId The ID of the AuthNRequest sent by this SP to the IdP
     */
    public function processResponse($requestId = null)
    {
        $this->_errors = array();
        if (isset($_POST) && isset($_POST['SAMLResponse'])) {
            // AuthnResponse -- HTTP_POST Binding
            $response = new OneLogin_Saml2_Response($this->_settings, $_POST['SAMLResponse']);

            if ($response->isValid($requestId)) {
                $this->_attributes = $response->getAttributes();
                $this->_nameid = $response->getNameId();
                $this->_authenticated = true;
            } else {
                $this->_errors[] = 'invalid_response';
            }
        } else {
            $this->_errors[] = 'invalid_binding';
            throw new OneLogin_Saml2_Error(
                'SAML Response not found, Only supported HTTP_POST Binding',
                OneLogin_Saml2_Error::SAML_RESPONSE_NOT_FOUND
            );
        }
    }

    /**
     * Process the SAML Logout Response / Logout Request sent by the IdP.
     *
     * @param boolean $keepLocalSession When false will destroy the local session, otherwise will destroy it
     * @param string  $requestId        The ID of the LogoutRequest sent by this SP to the IdP
     */
    public function processSLO($keepLocalSession = false, $requestId = null)
    {
        $this->_errors = array();
        if (isset($_GET) && isset($_GET['SAMLResponse'])) {
            $logoutResponse = new OneLogin_Saml2_LogoutResponse($this->_settings, $_GET['SAMLResponse']);
            if (!$logoutResponse->isValid($requestId)) {
                $this->_errors[] = 'invalid_logout_response';
            } else if ($logoutResponse->getStatus() !== OneLogin_Saml2_Constants::STATUS_SUCCESS) {
                $this->_errors[] = 'logout_not_success';
            } else {
                if (!$keepLocalSession) {
                    OneLogin_Saml2_Utils::deleteLocalSession();
                }
            }
        } else if (isset($_GET) && isset($_GET['SAMLRequest'])) {
            $decoded = base64_decode($_GET['SAMLRequest']);
            $request = gzinflate($decoded);
            if (!OneLogin_Saml2_LogoutRequest::isValid($this->_settings, $request)) {
                $this->_errors[] = 'invalid_logout_request';
            } else {
                if (!$keepLocalSession) {
                    OneLogin_Saml2_Utils::deleteLocalSession();
                }

                $inResponseTo = OneLogin_Saml2_LogoutRequest::getID($request);
                $responseBuilder = new OneLogin_Saml2_LogoutResponse($this->_settings);
                $responseBuilder->build($inResponseTo);
                $logoutResponse = $responseBuilder->getResponse();

                $parameters = array('SAMLResponse' => $logoutResponse);
                if (isset($_GET['RelayState'])) {
                    $parameters['RelayState'] = $_GET['RelayState'];
                }

                $security = $this->_settings->getSecurityData();
                if (isset($security['logoutResponseSigned']) && $security['logoutResponseSigned']) {
                    $signature = $this->buildResponseSignature($logoutResponse, $parameters['RelayState']);
                    $parameters['SigAlg'] = XMLSecurityKey::RSA_SHA1;
                    $parameters['Signature'] = $signature;
                }

                $this->redirectTo($this->getSLOurl(), $parameters);
            }
        } else {
            $this->_errors[] = 'invalid_binding';
            throw new OneLogin_Saml2_Error(
                'SAML LogoutRequest/LogoutResponse not found. Only supported HTTP_REDIRECT Binding',
                OneLogin_Saml2_Error::SAML_LOGOUTMESSAGE_NOT_FOUND
            );
        }
    }

    /**
     * Redirects the user to the url past by parameter
     * or to the url that we defined in our SSO Request.
     *
     * @param string $url        The target URL to redirect the user.
     * @param array  $parameters Extra parameters to be passed as part of the url
     */
    public function redirectTo($url = '', $parameters = array())
    {
        assert('is_string($url)');
        assert('is_array($parameters)');

        if (empty($url) && isset($_REQUEST['RelayState'])) {
            $url = $_REQUEST['RelayState'];
        }

        OneLogin_Saml2_Utils::redirect($url, $parameters);
    }

    /**
     * Checks if the user is authenticated or not.
     *
     * @return boolean  True if the user is authenticated
     */
    public function isAuthenticated()
    {
        return $this->_authenticated;
    }

    /**
     * Returns the set of SAML attributes.
     *
     * @return array  Attributes of the user.
     */
    public function getAttributes()
    {
        return $this->_attributes;
    }

    /**
     * Returns the nameID
     *
     * @return string  The nameID of the assertion
     */
    public function getNameId()
    {
        return $this->_nameid;
    }

    /**
     * Returns if there were any error
     *
     * @return array  Errors
     */
    public function getErrors()
    {
        return $this->_errors;
    }

    /**
     * Returns the requested SAML attribute
     *
     * @param string $name The requested attribute of the user.
     *
     * @return NULL || array Requested SAML attribute ($name).
     */
    public function getAttribute($name)
    {
        assert('is_string($name)');

        $value = null;
        if (isset($this->_attributes[$name])) {
            return $this->_attributes[$name];
        }
        return $value;
    }

    /**
     * Initiates the SSO process.
     *
     * @param string $returnTo   The target URL the user should be returned to after login.
     * @param array  $parameters An array of additional parameters to send through to the IdP
     */
    public function login($returnTo = null, $parameters = [])
    {
        assert('is_array($parameters)');

        $authnRequest = new OneLogin_Saml2_AuthnRequest($this->_settings);
        $idpData = $this->_settings->getIdPData();

        if (isset($idpData['parameters'])) {
            assert('is_array($idpData[\'parameters\'])');

            foreach ($idpData['parameters'] as $key => $val) {
                assert('is_string($key)');
                assert('is_string($val) || is_numeric($val)');

                $parameters[$key] = $val;
            }
        }

        $samlRequest = $authnRequest->getRequest();
        $parameters['SAMLRequest'] = $samlRequest;

        if (!empty($returnTo)) {
            $parameters['RelayState'] = $returnTo;
        } else {
            $parameters['RelayState'] = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        }

        $security = $this->_settings->getSecurityData();
        if (isset($security['authnRequestsSigned']) && $security['authnRequestsSigned']) {
            $signature = $this->buildRequestSignature($samlRequest, $parameters['RelayState']);
            $parameters['SigAlg'] = XMLSecurityKey::RSA_SHA1;
            $parameters['Signature'] = $signature;
        }
        $this->redirectTo($this->getSSOurl(), $parameters);
    }

    /**
     * Initiates the SLO process.
     *
     * @param string $returnTo The target URL the user should be returned to after logout.
     */
    public function logout($returnTo = null)
    {
        $sloUrl = $this->getSLOurl();
        if (!isset($sloUrl)) {
            throw new OneLogin_Saml2_Error(
                'The IdP does not support Single Log Out',
                OneLogin_Saml2_Error::SAML_SINGLE_LOGOUT_NOT_SUPPORTED
            );
        }

        $logoutRequest = new OneLogin_Saml2_LogoutRequest($this->_settings);

        $samlRequest = $logoutRequest->getRequest();

        $parameters = array('SAMLRequest' => $samlRequest);
        if (!empty($returnTo)) {
            $parameters['RelayState'] = $returnTo;
        } else {
            $parameters['RelayState'] = OneLogin_Saml2_Utils::getSelfURLNoQuery();
        }

        $security = $this->_settings->getSecurityData();
        if (isset($security['logoutRequestSigned']) && $security['logoutRequestSigned']) {
            $signature = $this->buildRequestSignature($samlRequest, $parameters['RelayState']);
            $parameters['SigAlg'] = XMLSecurityKey::RSA_SHA1;
            $parameters['Signature'] = $signature;
        }

        $this->redirectTo($sloUrl, $parameters);
    }

    /**
     * Gets the SSO url.
     *
     * @return string The url of the Single Sign On Service
     */
    public function getSSOurl()
    {
        $idpData = $this->_settings->getIdPData();
        return $idpData['singleSignOnService']['url'];
    }

    /**
     * Gets the SLO url.
     *
     * @return string The url of the Single Logout Service
     */
    public function getSLOurl()
    {
        $url = null;
        $idpData = $this->_settings->getIdPData();
        if (isset($idpData['singleLogoutService']) && isset($idpData['singleLogoutService']['url'])) {
            $url = $idpData['singleLogoutService']['url'];
        }
        return $url;
    }

    /**
     * Generates the Signature for a SAML Request
     *
     * @param string $samlRequest The SAML Request
     * @param string $relayState  The RelayState
     *
     * @return string A base64 encoded signature
     */
    public function buildRequestSignature($samlRequest, $relayState)
    {
        if (!$this->_settings->checkSPCerts()) {
            throw new OneLogin_Saml2_Error(
                "Trying to sign the SAML Request but can't load the SP certs",
                OneLogin_Saml2_Error::SP_CERTS_NOT_FOUND
            );
        }

        $key = $this->_settings->getSPkey();

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $objKey->loadKey($key, false);

        $msg = 'SAMLRequest='.urlencode($samlRequest);
        $msg .= '&RelayState='.urlencode($relayState);
        $msg .= '&SigAlg=' . urlencode(XMLSecurityKey::RSA_SHA1);
        $signature = $objKey->signData($msg);
        return base64_encode($signature);
    }

    /**
     * Generates the Signature for a SAML Response
     *
     * @param string $samlResponse The SAML Response
     * @param string $relayState   The RelayState
     *
     * @return string A base64 encoded signature
     */
    public function buildResponseSignature($samlResponse, $relayState)
    {
        if (!$this->_settings->checkSPCerts()) {
            throw new OneLogin_Saml2_Error(
                "Trying to sign the SAML Response but can't load the SP certs",
                OneLogin_Saml2_Error::SP_CERTS_NOT_FOUND
            );
        }

        $key = $this->_settings->getSPkey();

        $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $objKey->loadKey($key, false);

        $msg = 'SAMLResponse='.urlencode($samlResponse);
        $msg .= '&RelayState='.urlencode($relayState);
        $msg .= '&SigAlg=' . urlencode(XMLSecurityKey::RSA_SHA1);
        $signature = $objKey->signData($msg);
        return base64_encode($signature);
    }
}
