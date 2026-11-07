<?php

/**
 * Router of the PHP built-in web server that OneLogin_Saml2_RedirectionTest starts.
 *
 * It executes, without $stay, the toolkit method that is selected with the "case" parameter: the
 * redirection really happens (the headers are sent in the HTTP response and exit() ends the script),
 * something that can not be checked inside the PHPUnit process. If the redirection does not end the
 * script, the response has a body.
 */

require_once __DIR__ . '/bootstrap.php';

include TEST_ROOT . '/settings/settings1.php';

$case = isset($_GET['case']) ? $_GET['case'] : '';

switch ($case) {
    case 'utils':
        OneLogin_Saml2_Utils::redirect(
            'http://sp.example.com/path?x=1',
            array('a' => 'b c', 'flag' => null, 'list' => array('1', '2'))
        );
        break;
    case 'utils_long_url':
        OneLogin_Saml2_Utils::redirect('http://sp.example.com/path', array('long' => str_repeat('a', 5000)));
        break;
    case 'utils_relative':
        OneLogin_Saml2_Utils::redirect('/relative/path', array('a' => 'b'));
        break;
    case 'redirect_to':
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->redirectTo('http://sp2.example.com/target', array('a' => 'b'));
        break;
    case 'redirect_to_relay_state':
        // The RelayState of the request ($_REQUEST) is the target
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->redirectTo();
        break;
    case 'login':
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->login('http://sp.example.com/relaystate', array('extra' => 'value'));
        break;
    case 'login_signed':
        $settingsInfo['security']['authnRequestsSigned'] = true;
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->login('http://sp.example.com/relaystate');
        break;
    case 'logout':
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->logout('http://sp.example.com/relaystate', array(), 'my_name_id', '_51be37965feb5579d803141076936dc2e9d1d98ebf');
        break;
    case 'process_slo':
        // A valid Logout Request is answered with a Logout Response
        $_GET['SAMLRequest'] = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_deflated.xml.base64');
        $auth = new OneLogin_Saml2_Auth($settingsInfo);
        $auth->processSLO(true);
        break;
    default:
        http_response_code(400);
        echo 'Unknown case: ' . $case;
        exit();
}

echo 'The redirection did not end the script';
