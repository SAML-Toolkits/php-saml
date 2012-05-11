<?php

define('TEST_ROOT', __DIR__);

define('XMLSECLIBS_DIR', '../ext/xmlseclibs/');
require_once XMLSECLIBS_DIR . 'xmlseclibs.php';

define('ONELOGIN_SAML_DIR', '../src/OneLogin/Saml/');
require_once ONELOGIN_SAML_DIR . 'AuthRequest.php';
require_once ONELOGIN_SAML_DIR . 'Response.php';
require_once ONELOGIN_SAML_DIR . 'Settings.php';
require_once ONELOGIN_SAML_DIR . 'XmlSec.php';

date_default_timezone_set('America/Los_Angeles');
