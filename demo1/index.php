<?php
 
/**
 *  SAML Handler
 */

session_start();

require_once dirname(dirname(__FILE__)).'/_toolkit_loader.php';

require_once 'settings.php';

$auth = new OneLogin_Saml2_Auth($settingsInfo);

if (isset($_GET['sso'])) {
    $auth->login();
} else if (isset($_GET['sso2'])) {
    $returnTo = $spBaseUrl.'/demo1/attrs.php';
    $auth->login($returnTo);
} else if (isset($_GET['slo'])) {
    $returnTo = null;
    $paramters = array();
    $nameId = null;
    $sessionIndex = null;
    if (isset($_SESSION['samlNameId'])) {
        $nameId = $_SESSION['samlNameId'];
    }
    if (isset($_SESSION['samlSessionIndex'])) {
        $sessionIndex = $_SESSION['samlSessionIndex'];
    }

    $auth->logout($returnTo, $paramters, $nameId, $sessionIndex);
} else if (isset($_GET['acs'])) {
    $auth->processResponse();

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        print_r('<p>'.implode(', ', $errors).'</p>');
    }

    if (!$auth->isAuthenticated()) {
        echo "<p>Not authenticated</p>";
        exit();
    }

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();        
    if (isset($_POST['RelayState']) && OneLogin_Saml2_Utils::getSelfURL() != $_POST['RelayState']) {
        $auth->redirectTo($_POST['RelayState']);
    }
} else if (isset($_GET['sls'])) {
    $auth->processSLO();
    $errors = $auth->getErrors();
    if (empty($errors)) {
        print_r('<p>Sucessfully logged out</p>');
    } else {
        print_r('<p>'.implode(', ', $errors).'</p>');
    }
}

if (isset($_SESSION['samlUserdata'])) {
    if (!empty($_SESSION['samlUserdata'])) {
        $attributes = $_SESSION['samlUserdata'];
        echo 'You have the following attributes:<br>';
        echo '<table><thead><th>Name</th><th>Values</th></thead><tbody>';
        foreach ($attributes as $attributeName => $attributeValues) {
            echo '<tr><td>' . htmlentities($attributeName) . '</td><td><ul>';
            foreach ($attributeValues as $attributeValue) {
                echo '<li>' . htmlentities($attributeValue) . '</li>';
            }
            echo '</ul></td></tr>';
        }
        echo '</tbody></table>';
    } else {
        echo "<p>You don't have any attribute</p>";
    }

    echo '<p><a href="?slo" >Logout</a></p>';
} else {
    echo '<p><a href="?sso" >Login</a></p>';
    echo '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
}
