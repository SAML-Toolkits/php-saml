<?php
/**
 * SAMPLE Code to demonstrate how to handle a SAML assertion response.
 *
 * Your IdP will usually want your metadata, you can use this code to generate it once,
 * or expose it on a URL so your IdP can check it periodically.
 */

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\Metadata;
use OneLogin\Saml2\Settings;

$samlSettings = new Settings();
$sp = $samlSettings->getSPData();

$samlMetadata = Metadata::builder($sp);

return new \GuzzleHttp\Psr7\Response(200, ['Content-Type' => 'text/xml'], $samlMetadata);
