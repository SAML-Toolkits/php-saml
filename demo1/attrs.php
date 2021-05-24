<?php

session_start();
$html = '';
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

    $html .= '<p><a href="index.php?slo" >Logout</a></p>';
} else {
    $html .= '<p><a href="index.php?sso2" >Login and access later to this page</a></p>';
}

return new \GuzzleHttp\Psr7\Response(200, [], $html);