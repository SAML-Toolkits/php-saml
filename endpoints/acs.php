<?php

/**
 *  SP Assertion Consumer Service Endpoint
 */

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

$auth = new OneLogin_Saml2_Auth();

$auth->processResponse();

$errors = $auth->getErrors();

if (!empty($errors)) {
    echo '<p>', htmlentities(implode(', ', $errors)), '</p>';
    exit();
}

if (!$auth->isAuthenticated()) {
    echo "<p>Not authenticated</p>";
    exit();
}

$_SESSION['samlUserdata'] = $auth->getAttributes();
$_SESSION['IdPSessionIndex'] = $auth->getSessionIndex();
if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
    // To avoid 'Open Redirect' attacks, before execute the
    // redirection confirm the value of $_POST['RelayState'] is a // trusted URL.
    $auth->redirectTo($_POST['RelayState']);
}

$attributes = $_SESSION['samlUserdata'];

if (!empty($attributes)) {
    echo '<h1>'._('User attributes:').'</h1>';
    echo '<table><thead><th>'._('Name').'</th><th>'._('Values').'</th></thead><tbody>';
    foreach ($attributes as $attributeName => $attributeValues) {
        echo '<tr><td>'.htmlentities($attributeName).'</td><td><ul>';
        foreach ($attributeValues as $attributeValue) {
            echo '<li>'.htmlentities($attributeValue).'</li>';
        }
        echo '</ul></td></tr>';
    }
    echo '</tbody></table>';
    if (!empty($_SESSION['IdPSessionIndex'])) {
        echo '<p>The SessionIndex of the IdP is: '.htmlentities($_SESSION['IdPSessionIndex']).'</p>';
    }
} else {
    echo _('Attributes not found');
}
