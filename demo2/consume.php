<?php
/**
 * SAMPLE Code to demonstrate how to handle a SAML assertion response.
 *
 * The URL of this file will have been given during the SAML authorization.
 * After a successful authorization, the browser will be directed to this
 * link where it will send a certified response via $_POST.
 */

require_once dirname(__DIR__).'/_toolkit_loader.php';

use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;

/** @var \GuzzleHttp\Psr7\ServerRequest $request */
$request = \GuzzleHttp\Psr7\ServerRequest::fromGlobals();
$html = '';

try {
    if (isset($request->getParsedBody()['SAMLResponse'])) {
        $samlSettings = new Settings();
        $samlResponse = new Response($samlSettings, $request->getParsedBody()['SAMLResponse']);
        if ($samlResponse->isValid()) {
            $html .= 'You are: ' . $samlResponse->getNameId() . '<br>';
            $attributes = $samlResponse->getAttributes();
            if (!empty($attributes)) {
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
            }
        } else {
            $html .= 'Invalid SAML Response';
        }
    } else {
        $html .= 'No SAML Response found in POST.';
    }
    return new \GuzzleHttp\Psr7\Response(200, [], 'Invalid SAML Response: ' . $html);
} catch (Exception $e) {
    return new \GuzzleHttp\Psr7\Response(400, [], 'Invalid SAML Response: ' . $e->getMessage());
}
