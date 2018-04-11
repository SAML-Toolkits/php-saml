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

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

$auth = new OneLogin\Saml2\Auth();

if (!isset($_SESSION['samlUserdata'])) {
    $auth->login();
} else {
    $indexUrl = str_replace('/sso.php', '/index.php', Utils::getSelfURLNoQuery());
    Utils::redirect($indexUrl);
}
