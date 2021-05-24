<?php
 
/**
 *  SAML Handler
 */

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Utils;

require_once 'settings.php';

$auth = new Auth($settingsInfo);

/** @var \GuzzleHttp\Psr7\ServerRequest $request */
$request = \GuzzleHttp\Psr7\ServerRequest::fromGlobals();

if (isset($request->getQueryParams()['sso'])) {
    return $auth->login();
    # If AuthNRequest ID need to be saved in order to later validate it, do instead
    # $ssoBuiltUrl = $auth->login(null, array(), false, false, true);
    # $_SESSION['AuthNRequestID'] = $auth->getLastRequestID();
    # return new \GuzzleHttp\Psr7\Response(302, [
    #   'Pragma' => 'no-cache',
    #   'Cache-Control' => 'no-cache, must-revalidate',
    #   'location' => [(string) $ssoBuiltUrl]
    #]);


} else if (isset($request->getQueryParams()['sso2'])) {
    $returnTo = $spBaseUrl.'/demo1/attrs.php';
    return $auth->login($returnTo);
} else if (isset($request->getQueryParams()['slo'])) {
    $returnTo = null;
    $paramters = array();
    $nameId = null;
    $sessionIndex = null;
    $nameIdFormat = null;
    $nameIdNameQualifier = null;
    $nameIdSPNameQualifier = null;

    if (isset($_SESSION['samlNameId'])) {
        $nameId = $_SESSION['samlNameId'];
    }
    if (isset($_SESSION['samlNameIdFormat'])) {
        $nameIdFormat = $_SESSION['samlNameIdFormat'];
    }
    if (isset($_SESSION['samlNameIdNameQualifier'])) {
        $nameIdNameQualifier = $_SESSION['samlNameIdNameQualifier'];
    }
    if (isset($_SESSION['samlNameIdSPNameQualifier'])) {
        $nameIdSPNameQualifier = $_SESSION['samlNameIdSPNameQualifier'];
    }
    if (isset($_SESSION['samlSessionIndex'])) {
        $sessionIndex = $_SESSION['samlSessionIndex'];
    }

    return $auth->logout($returnTo, $paramters, $nameId, $sessionIndex, false, $nameIdFormat, $nameIdNameQualifier, $nameIdSPNameQualifier);

    # If LogoutRequest ID need to be saved in order to later validate it, do instead
    # $sloBuiltUrl = $auth->logout(null, $paramters, $nameId, $sessionIndex, true);
    # $_SESSION['LogoutRequestID'] = $auth->getLastRequestID();
    # header('Pragma: no-cache');
    # header('Cache-Control: no-cache, must-revalidate');
    # header('Location: ' . $sloBuiltUrl);
    # exit();

} else if (isset($request->getQueryParams()['acs'])) {
    if (isset($_SESSION) && isset($_SESSION['AuthNRequestID'])) {
        $requestID = $_SESSION['AuthNRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processResponse($requestID);

    $errors = $auth->getErrors();

    if (!empty($errors)) {
        $html = '<p>' . implode(', ', $errors) . '</p>';
        if ($auth->getSettings()->isDebugActive()) {
            $html .= '<p>'.$auth->getLastErrorReason().'</p>';
        }
        return new \GuzzleHttp\Psr7\Response(500, [], $html);
    }

    if (!$auth->isAuthenticated()) {
        return new \GuzzleHttp\Psr7\Response(401, [], '<p>Not authenticated</p>');
    }

    $_SESSION['samlUserdata'] = $auth->getAttributes();
    $_SESSION['samlNameId'] = $auth->getNameId();
    $_SESSION['samlNameIdFormat'] = $auth->getNameIdFormat();
    $_SESSION['samlNameIdNameQualifier'] = $auth->getNameIdNameQualifier();
    $_SESSION['samlNameIdSPNameQualifier'] = $auth->getNameIdSPNameQualifier();
    $_SESSION['samlSessionIndex'] = $auth->getSessionIndex();

    unset($_SESSION['AuthNRequestID']);
    $relayState = $request->getParsedBody()['RelayState'] ?? null;
    if ($relayState !== null && Utils::getSelfURL() !== $relayState) {
        return $auth->redirectTo($relayState);
    }
} else if (isset($request->getQueryParams()['sls'])) {
    if (isset($_SESSION) && isset($_SESSION['LogoutRequestID'])) {
        $requestID = $_SESSION['LogoutRequestID'];
    } else {
        $requestID = null;
    }

    $auth->processSLO(false, $requestID);
    $errors = $auth->getErrors();
    if (empty($errors)) {
        $html = '<p>Sucessfully logged out</p>';
    } else {
        $html = '<p>' . implode(', ', $errors) . '</p>';
        if ($auth->getSettings()->isDebugActive()) {
            $html .= '<p>'.$auth->getLastErrorReason().'</p>';
        }
    }
}

if (isset($_SESSION['samlUserdata'])) {
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
    } else {
        $html .= "<p>You don't have any attribute</p>";
    }

    $html .= '<p><a href="?slo" >Logout</a></p>';
} else {
    $html .= '<p><a href="?sso" >Login</a></p>';
    $html .= '<p><a href="?sso2" >Login and access to attrs.php page</a></p>';
}

return new \GuzzleHttp\Psr7\Response(200, [], $html);