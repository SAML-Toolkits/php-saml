<?php

define('TEST_ROOT', __DIR__);

define('XMLSECLIBS_DIR', './../ext/xmlseclibs/');
require XMLSECLIBS_DIR . 'xmlseclibs.php';

define('ONELOGIN_SAML_DIR', './../src/OneLogin/Saml/');
require ONELOGIN_SAML_DIR . 'AuthRequest.php';
require ONELOGIN_SAML_DIR . 'Response.php';
require ONELOGIN_SAML_DIR . 'Settings.php';
require ONELOGIN_SAML_DIR . 'XmlSec.php';

date_default_timezone_set('America/Los_Angeles');