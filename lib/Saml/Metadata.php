<?php

use Psr\Log\LoggerInterface;

class OneLogin_Saml_Metadata
{
    const VALIDITY_SECONDS = 604800; // 1 week

    protected $_settings;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @param LoggerInterface $logger
     * @param array|object|null        $settings Setting data
     */
    public function __construct(LoggerInterface $logger, $settings = null)
    {
        $this->logger = $logger;
        $auth = new OneLogin_Saml2_Auth($this->logger, $settings);
        $this->_settings = $auth->getSettings();
    }

    /**
     * @return string
     *
     * @throws OneLogin_Saml2_Error
     */
    public function getXml()
    {
        return $this->_settings->getSPMetadata();
    }

    /**
     * @return string
     */
    protected function _getMetadataValidTimestamp()
    {
        $timeZone = date_default_timezone_get();
        date_default_timezone_set('UTC');
        $time = strftime("%Y-%m-%dT%H:%M:%SZ", time() + self::VALIDITY_SECONDS);
        date_default_timezone_set($timeZone);
        return $time;
    }
}
