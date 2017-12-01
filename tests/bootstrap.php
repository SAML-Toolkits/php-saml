<?php

include ('compatibility.php');

ob_start();

$basePath = dirname(__DIR__);

require_once $basePath.'/_toolkit_loader.php';

if (!defined('TEST_ROOT')) {
    define('TEST_ROOT', __DIR__);
}

if (!defined('ONELOGIN_CUSTOMPATH')) {
    define('ONELOGIN_CUSTOMPATH', __DIR__.'/data/customPath/');
}

date_default_timezone_set('America/Los_Angeles');


if (!function_exists('getUrlFromRedirect')) {
    /**
    * In phpunit when a redirect is executed an Excepion raise,
    * this funcion Get the target URL of the redirection
    *
    * @param array $trace Trace of the Stack when an Exception raised
    *
    * @return string $targeturl Target url of the redirection
    */
    function getUrlFromRedirect($trace)
    {
        $param_args = $trace[0]['args'][4];
        $targeturl = $param_args['url'];
        return $targeturl;
    }
}

if (!function_exists('getParamsFromUrl')) {
    /**
    * Parsed the Query parameters of an URL.
    *
    * @param string $url The URL
    *
    * @return array $parsedQuery Parsed query of the url
    */
    function getParamsFromUrl($url)
    {
        $parsedQuery = null;
        $parsedUrl = parse_url($url);
        if (isset($parsedUrl['query'])) {
            $query = $parsedUrl['query'];
            parse_str($query, $parsedQuery);
        }
        return $parsedQuery;
    }
}
