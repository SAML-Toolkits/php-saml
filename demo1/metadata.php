<?php
 
/**
 *  SAML Metadata view
 */

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Error;

require_once 'settings.php' ;

try {
    #$auth = new OneLogin\Saml2\Auth($settingsInfo);
    #$settings = $auth->getSettings();
    // Now we only validate SP settings
    $settings = new Settings($settingsInfo, true);
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
	    return new \GuzzleHttp\Psr7\Response(500, ['Content-Type', 'text/xml'], $metadata);
    } else {
        throw new Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
	return new \GuzzleHttp\Psr7\Response(500, [], $e->getMessage());
}
