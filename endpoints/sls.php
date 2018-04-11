<?php
 
/**
 *  SP Single Logout Service Endpoint
 */

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\Auth;

$auth = new Auth();

$auth->processSLO();

$errors = $auth->getErrors();

if (empty($errors)) {
    echo 'Sucessfully logged out';
} else {
    echo implode(', ', $errors);
}
