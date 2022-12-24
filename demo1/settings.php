<?php

    $spBaseUrl = 'https://aoprototest-php.azurewebsites.net';

    $settingsInfo = array(
        'sp' => array(
            'entityId' => $spBaseUrl.'/demo1/metadata.php',
            'assertionConsumerService' => array(
                'url' => $spBaseUrl.'/demo1/index.php?acs',
            ),
            'singleLogoutService' => array(
                'url' => $spBaseUrl.'/demo1/index.php?sls',
            ),
            'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
        ),
        'idp' => array(
            'entityId' => 'https://samltoolkit.azurewebsites.net',
            'singleSignOnService' => array(
                'url' => '',
            ),
            'singleLogoutService' => array(
                'url' => '',
            ),
            'x509cert' => '',
        ),
    );
