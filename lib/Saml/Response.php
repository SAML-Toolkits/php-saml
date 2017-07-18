<?php

use Psr\Log\LoggerInterface;

class OneLogin_Saml_Response extends OneLogin_Saml2_Response
{
    /**
     * Constructor that process the SAML Response,
     * Internally initializes an SP SAML instance
     * and an OneLogin_Saml2_Response.
     *
     * @param array|object    $oldSettings Settings
     * @param string          $assertion   SAML Response
     * @param LoggerInterface $logger
     */
    public function __construct($oldSettings, $assertion, LoggerInterface $logger)
    {
        $auth = new OneLogin_Saml2_Auth($logger, $oldSettings);
        $settings = $auth->getSettings();
        parent::__construct($settings, $assertion, $logger);
    }

    /**
     * Retrieves an Array with the logged user data.
     *
     * @return array
     */
    public function get_saml_attributes()
    {
        return $this->getAttributes();
    }

    /**
     * Retrieves the nameId
     *
     * @return string
     */
    public function get_nameid()
    {
        return $this->getNameId();
    }
}
