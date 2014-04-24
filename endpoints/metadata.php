<?php
 
/**
 *  SP Metadata Endpoint
 */

require_once dirname(dirname(__FILE__)).'/_toolkit_loader.php';

try {
    $auth = new Onelogin_Saml2_Auth();
    $settings = $auth->getSettings();
    $metadata = $settings->getSPMetadata();
    $errors = $settings->validateMetadata($metadata);
    if (empty($errors)) {
        header('Content-Type: text/xml');
        echo $metadata;
    } else {
        throw new Onelogin_Saml2_Error(
            'Invalid SP metadata: '.implode(', ', $errors),
            Onelogin_Saml2_Error::METADATA_SP_INVALID
        );
    }
} catch (Exception $e) {
    echo $e->getMessage();
}
