<?php
/**
 * SAMPLE Code to demonstrate how to initiate a SAML Single Log Out request
 *
 * When the user visits this URL, the browser will be redirected to the SLO
 * IdP with an SLO request.
 */

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

$samlSettings = new Settings();

$idpData = $samlSettings->getIdPData();
if (isset($idpData['singleLogoutService']) && isset($idpData['singleLogoutService']['url'])) {
    $sloUrl = $idpData['singleLogoutService']['url'];
} else {
    throw new Exception("The IdP does not support Single Log Out");
}

if (isset($_SESSION['IdPSessionIndex']) && !empty($_SESSION['IdPSessionIndex'])) {
    $logoutRequest = new LogoutRequest($samlSettings, null, $_SESSION['IdPSessionIndex']);
} else {
    $logoutRequest = new LogoutRequest($samlSettings);
}

$samlRequest = $logoutRequest->getRequest();

$parameters = array('SAMLRequest' => $samlRequest);

$url = Utils::redirect($sloUrl, $parameters, true);

header("Location: $url");
