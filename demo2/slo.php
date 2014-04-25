<?php
/**
 * SAMPLE Code to demonstrate how to initiate a SAML Single Log Out request
 *
 * When the user visits this URL, the browser will be redirected to the SLO
 * IdP with an SLO request.
 */

require_once '../_toolkit_loader.php';

$settings = new OneLogin_Saml2_Settings();

$idpData = $settings->getIdPData();
if (isset($idpData['singleLogoutService']) && isset($idpData['singleLogoutService']['url'])) {
    $sloUrl = $idpData['singleLogoutService']['url'];
} else {
    throw new Exception("The IdP does not support Single Log Out");
}

$logoutRequest = new OneLogin_Saml2_LogoutRequest($settings);
$samlRequest = $logoutRequest->getRequest();

$parameters = array('SAMLRequest' => $samlRequest);

$url = OneLogin_Saml2_Utils::redirect($sloUrl, $parameters, true);

header("Location: $url");
