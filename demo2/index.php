<?php
/**
 * SAMPLE Code to demonstrate how to initiate a SAML Authorization request
 *
 * When the user visits this URL, the browser will be redirected to the SSO
 * IdP with an authorization request. If successful, it will then be
 * redirected to the consume URL (specified in settings) with the auth
 * details.
 */

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\AuthnRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;

/** @var \GuzzleHttp\Psr7\ServerRequest $request */
$request = \GuzzleHttp\Psr7\ServerRequest::fromGlobals();

if (!isset($_SESSION['samlUserdata'])) {
    $settings = new Settings();
    $authRequest = new AuthnRequest($settings);
    $samlRequest = $authRequest->getRequest();

    $parameters = array('SAMLRequest' => $samlRequest);
    $parameters['RelayState'] = Utils::getSelfURLNoQuery();

    $idpData = $settings->getIdPData();
    $ssoUrl = $idpData['singleSignOnService']['url'];
    return Utils::redirect($ssoUrl, $parameters);
} else {
    $html = '';
    if (!empty($_SESSION['samlUserdata'])) {
        $attributes = $_SESSION['samlUserdata'];
        $html .= 'You have the following attributes:<br>';
        $html .= '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
        foreach ($attributes as $attributeName => $attributeValues) {
            $html .= '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
            foreach ($attributeValues as $attributeValue) {
                $html .= '<li>' . htmlentities($attributeValue) . '</li>';
            }
            $html .= '</ul></td></tr>';
        }
        $html .= '</tbody></table>';
        if (!empty($_SESSION['IdPSessionIndex'])) {
            $html .= '<p>The SessionIndex of the IdP is: '.$_SESSION['IdPSessionIndex'].'</p>';
        }
    } else {
        $html .= "<p>You don't have any attribute</p>";
    }
    $html .= '<p><a href="slo.php">Logout</a></p>';

    return new \GuzzleHttp\Psr7\Response(200, [], $html);
}
