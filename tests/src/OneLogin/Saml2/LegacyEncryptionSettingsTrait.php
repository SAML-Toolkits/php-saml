<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Settings;

trait LegacyEncryptionSettingsTrait
{
    /**
     * @param array $settingsInfo
     *
     * @return Settings
     */
    protected function createLegacyEncryptionSettingsInfo(array $settingsInfo)
    {
        if (!isset($settingsInfo['security'])) {
            $settingsInfo['security'] = array();
        }
        $settingsInfo['security']['allowRSA15KeyTransport'] = true;

        return $settingsInfo;
    }

    protected function createLegacyEncryptionSettings(array $settingsInfo)
    {
        return new Settings($this->createLegacyEncryptionSettingsInfo($settingsInfo));
    }
}
