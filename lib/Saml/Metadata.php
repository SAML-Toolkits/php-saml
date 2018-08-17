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
        $timestamp = time() + self::VALIDITY_SECONDS;
        $date = new DateTime("@$timestamp", new DateTimeZone('UTC'));
        $time = $date->format("Y-m-d\TH:i:s\Z");
        return $time;
    }
}
