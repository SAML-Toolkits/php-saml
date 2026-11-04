<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Constants;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use DOMDocument;
use DOMElement;

trait EncryptedNameIdTrait
{
    /**
     * Encrypts an element for the SP of the test settings.
     *
     * @param string|DOMElement $xml     Element to encrypt (as a node it is serialized without the namespaces declared by its ancestors)
     * @param string      $keyTransport  Key transport algorithm
     * @param string|null $wrappedKey    Raw bytes to wrap in the EncryptedKey instead of the real session key
     * @param bool        $garbageKey    Replace the EncryptedKey CipherValue with random bytes
     * @param string      $dataAlgorithm Data encryption algorithm (a 128 bit one)
     *
     * @return string xenc:EncryptedData element
     */
    protected function encryptForSP($xml, $keyTransport = XMLSecurityKey::RSA_OAEP_MGF1P, $wrappedKey = null, $garbageKey = false, $dataAlgorithm = XMLSecurityKey::AES128_GCM)
    {
        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');

        if ($xml instanceof DOMElement) {
            $node = $xml;
        } else {
            $doc = new DOMDocument();
            $doc->loadXML($xml);
            $node = $doc->documentElement;
        }

        $enc = new XMLSecEnc();
        $enc->setNode($node);
        $enc->type = XMLSecEnc::Element;

        // GCM by default, so a wrong session key always fails the same way
        $symmetricKey = new XMLSecurityKey($dataAlgorithm);
        $symmetricKey->generateSessionKey();

        $keyToWrap = $symmetricKey;
        if ($wrappedKey !== null) {
            $keyToWrap = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
            $keyToWrap->key = $wrappedKey;
        }

        $transportKey = new XMLSecurityKey($keyTransport, array('type' => 'public'));
        $transportKey->loadKey($cert);
        $enc->encryptKey($transportKey, $keyToWrap);
        $encryptedData = $enc->encryptNode($symmetricKey);

        if ($garbageKey) {
            $encryptedKey = $encryptedData->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
            $encryptedKey->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'CipherValue')->item(0)->nodeValue = base64_encode(random_bytes(128));
        }

        return $encryptedData->ownerDocument->saveXML($encryptedData);
    }

    /**
     * @return string saml:EncryptedID element
     */
    protected function buildEncryptedNameId($keyTransport = XMLSecurityKey::RSA_OAEP_MGF1P, $wrappedKey = null, $garbageKey = false)
    {
        $nameId = '<saml:NameID xmlns:saml="' . Constants::NS_SAML . '">ONELOGIN_9c86c4542ab9d6fce07f2f7fd335287b9b3cdf69</saml:NameID>';

        return '<saml:EncryptedID xmlns:saml="' . Constants::NS_SAML . '">' . $this->encryptForSP($nameId, $keyTransport, $wrappedKey, $garbageKey) . '</saml:EncryptedID>';
    }

    /**
     * @param string $encryptedId saml:EncryptedID element
     *
     * @return string LogoutRequest XML
     */
    protected function buildLogoutRequestWithEncryptedId($encryptedId)
    {
        return '<samlp:LogoutRequest xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="ONELOGIN_21584ccdfaca36a145ae990442dcd96bfe60151e" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . $encryptedId
            . '</samlp:LogoutRequest>';
    }

    /**
     * @param string $encryptedId saml:EncryptedID element placed in the Subject of the encrypted Assertion
     *
     * @return string Base64 encoded Response with an EncryptedAssertion
     */
    protected function buildResponseWithEncryptedAssertion($encryptedId)
    {
        $assertion = '<saml:Assertion xmlns:saml="' . Constants::NS_SAML . '" ID="_cccd6024116641fe48e0ae2c51220d02755f96c98d" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<saml:Subject>' . $encryptedId . '</saml:Subject>'
            . '</saml:Assertion>';

        return base64_encode(
            '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_cccd6024116641fe48e0ae2c51220d02755f96c98e" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
            . '<saml:EncryptedAssertion>' . $this->encryptForSP($assertion) . '</saml:EncryptedAssertion>'
            . '</samlp:Response>'
        );
    }
}
