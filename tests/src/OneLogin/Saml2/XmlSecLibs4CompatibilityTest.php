<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Auth;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Response;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use phpseclib3\Crypt\PublicKeyLoader;
use RobRichards\XMLSecLibs\XMLSecEnc;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use DOMDocument;
use DOMXPath;
use Exception;

/**
 * xmlseclibs 4 parses the keys and the certificates with phpseclib and keeps them as PEM
 * strings, where xmlseclibs 3 used OpenSSL and kept OpenSSL handles. These tests exercise the
 * code of the toolkit that handles keys, with the formats and the algorithms that a deployment
 * may use and that the rest of the suite does not cover (it uses one 1024 bit PKCS#1 key).
 */
class XmlSecLibs4CompatibilityTest extends \PHPUnit\Framework\TestCase
{
    use LegacyEncryptionSettingsTrait;
    use EncryptedNameIdTrait;

    /**
     * @return array SP private key (the one of the tests) written in the formats that a settings file may contain
     */
    private function privateKeyFormats()
    {
        $pkcs1 = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key');
        $pkcs8 = str_replace("\r\n", "\n", PublicKeyLoader::load($pkcs1)->toString('PKCS8'));
        $withoutHeader = function ($pem) {
            return preg_replace('/\s+/', '', preg_replace('/-----(BEGIN|END) [A-Z ]+-----/', '', $pem));
        };

        return array(
            'PKCS#1 PEM' => $pkcs1,
            'PKCS#8 PEM' => $pkcs8,
            'PKCS#8 PEM with CRLF' => str_replace("\n", "\r\n", $pkcs8),
            'PKCS#1 without header' => $withoutHeader($pkcs1),
            'PKCS#8 without header' => $withoutHeader($pkcs8),
            'PKCS#8 in a single line' => preg_replace('/\s+/', ' ', trim($pkcs8)),
        );
    }

    public function privateKeyFormatProvider()
    {
        $cases = array();
        foreach (array_keys($this->privateKeyFormats()) as $name) {
            $cases[$name] = array($name);
        }

        return $cases;
    }

    /**
     * @param string $privateKey Private key of the SP
     *
     * @return array Settings where the key pair of the SP doubles as the key pair of the IdP
     */
    private function settingsInfoWithKey($privateKey)
    {
        include TEST_ROOT . '/settings/settings1.php';

        $cert = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt');
        $settingsInfo['sp']['privateKey'] = $privateKey;
        $settingsInfo['sp']['x509cert'] = $cert;
        $settingsInfo['idp']['x509cert'] = $cert;
        unset($settingsInfo['idp']['certFingerprint']);

        return $settingsInfo;
    }

    /**
     * HTTP-Redirect signatures with every signature algorithm (castKey is used when it is not
     * RSA-SHA1) and every format of the private key of the SP
     *
     * @dataProvider privateKeyFormatProvider
     *
     * @covers OneLogin\Saml2\Auth::buildRequestSignature
     * @covers OneLogin\Saml2\Utils::validateBinarySign
     * @covers OneLogin\Saml2\Utils::castKey
     */
    public function testRedirectSignatureWithPrivateKeyFormats($format)
    {
        $auth = new Auth($this->settingsInfoWithKey($this->privateKeyFormats()[$format]));
        $idpData = $auth->getSettings()->getIdPData();
        $samlRequest = base64_encode(gzdeflate('<samlp:LogoutRequest/>'));

        $algorithms = array(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::RSA_SHA256, XMLSecurityKey::RSA_SHA384, XMLSecurityKey::RSA_SHA512);
        foreach ($algorithms as $algorithm) {
            $getData = array(
                'SAMLRequest' => $samlRequest,
                'RelayState' => '/relay',
                'SigAlg' => $algorithm,
                'Signature' => $auth->buildRequestSignature($samlRequest, '/relay', $algorithm),
            );
            $this->assertTrue(Utils::validateBinarySign('SAMLRequest', $getData, $idpData), "$format, $algorithm");

            $getData['RelayState'] = '/tampered';
            $this->assertFalse(Utils::validateBinarySign('SAMLRequest', $getData, $idpData), "$format, $algorithm, tampered");
        }
    }

    /**
     * A key loaded for one algorithm can be used for another one, as a private key too
     *
     * @dataProvider privateKeyFormatProvider
     *
     * @covers OneLogin\Saml2\Utils::castKey
     */
    public function testCastKeyOfPrivateKey($format)
    {
        $privateKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));
        $privateKey->loadKey((new Settings($this->settingsInfoWithKey($this->privateKeyFormats()[$format])))->getSPkey());
        $publicKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA512, array('type' => 'public'));
        $publicKey->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt'), false, true);

        $castKey = Utils::castKey($privateKey, XMLSecurityKey::RSA_SHA512, 'private');
        $this->assertSame(XMLSecurityKey::RSA_SHA512, $castKey->type);
        $signature = $castKey->signData('data to sign');
        $this->assertSame(1, $publicKey->verifySignature('data to sign', $signature));
        $this->assertSame(0, $publicKey->verifySignature('other data', $signature));
    }

    /**
     * Enveloped signatures (Metadata, or any other element) with every signature and digest
     * algorithm and every format of the private key
     *
     * @dataProvider privateKeyFormatProvider
     *
     * @covers OneLogin\Saml2\Utils::addSign
     * @covers OneLogin\Saml2\Utils::validateSign
     */
    public function testXmlSignatureWithPrivateKeyFormats($format)
    {
        $settings = new Settings($this->settingsInfoWithKey($this->privateKeyFormats()[$format]));
        $idpData = $settings->getIdPData();
        $xml = '<samlp:AuthnRequest xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_request" Version="2.0" IssueInstant="2014-03-31T18:23:24Z"><saml:Issuer>http://stuff.com/endpoints/metadata.php</saml:Issuer></samlp:AuthnRequest>';

        $combinations = array(
            array(XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA256),
            array(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA1),
            array(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256),
            array(XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA512),
            array(XMLSecurityKey::RSA_SHA384, XMLSecurityDSig::SHA384),
            array(XMLSecurityKey::RSA_SHA512, XMLSecurityDSig::SHA512),
        );
        foreach ($combinations as $combination) {
            list($signatureAlgorithm, $digestAlgorithm) = $combination;
            $message = "$format, $signatureAlgorithm, $digestAlgorithm";

            $signed = Utils::addSign($xml, $settings->getSPkey(), $settings->getSPcert(), $signatureAlgorithm, $digestAlgorithm);
            $this->assertTrue(Utils::validateSign($signed, $idpData['x509cert']), $message);

            // The certificate that travels in the KeyInfo is identified by its fingerprint
            foreach (array('sha1', 'sha256') as $fingerprintAlgorithm) {
                $fingerprint = Utils::calculateX509Fingerprint($settings->getSPcert(), $fingerprintAlgorithm);
                $this->assertTrue(Utils::validateSign($signed, null, $fingerprint, $fingerprintAlgorithm), "$message, $fingerprintAlgorithm fingerprint");
            }

            // addSign sets its own ID, so the content (the Issuer) is the one that changes
            $tampered = str_replace('stuff.com', 'evil.example.com', $signed);
            $this->assertNotSame($signed, $tampered);
            $rejection = null;
            try {
                Utils::validateSign($tampered, $idpData['x509cert']);
            } catch (Exception $e) {
                $rejection = $e->getMessage();
            }
            $this->assertSame('Reference validation failed', $rejection, "$message, tampered");
        }
    }

    /**
     * Every data encryption algorithm for the NameID that the toolkit generates, decrypted with
     * every format of the private key
     *
     * @dataProvider privateKeyFormatProvider
     *
     * @covers OneLogin\Saml2\Utils::generateNameId
     * @covers OneLogin\Saml2\Utils::decryptElement
     * @covers OneLogin\Saml2\LogoutRequest::getNameId
     */
    public function testEncryptedNameIdWithPrivateKeyFormats($format)
    {
        $settings = new Settings($this->settingsInfoWithKey($this->privateKeyFormats()[$format]));

        $algorithms = array(
            XMLSecurityKey::AES128_CBC,
            XMLSecurityKey::AES192_CBC,
            XMLSecurityKey::AES256_CBC,
            XMLSecurityKey::TRIPLEDES_CBC,
            XMLSecurityKey::AES128_GCM,
            XMLSecurityKey::AES192_GCM,
            XMLSecurityKey::AES256_GCM,
        );
        foreach ($algorithms as $algorithm) {
            $encryptedId = Utils::generateNameId('user@example.com', 'http://stuff.com/endpoints/metadata.php', Constants::NAMEID_EMAIL_ADDRESS, $settings->getSPcert(), null, $algorithm);
            $logoutRequest = $this->buildLogoutRequestWithEncryptedId($encryptedId);

            $this->assertSame('user@example.com', LogoutRequest::getNameId($logoutRequest, $settings->getSPkey()), "$format, $algorithm");
        }
    }

    /**
     * When the key transport is not valid, the decryption goes on with a key derived from the
     * encrypted key and the private key of the SP (so a valid and an invalid key transport are
     * indistinguishable). Every failure is reported the same way, so the failure of a data
     * encrypted with another key can not tell that this derivation worked or not: this test
     * encrypts the data with the substitute key to see that it is used.
     *
     * @covers OneLogin\Saml2\Utils::decryptElement
     */
    public function testDecryptElementSubstitutesTheKeyOfAnInvalidKeyTransport()
    {
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
        $seckey->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));

        foreach (array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_1_5) as $keyTransport) {
            // The key transport is valid but wraps 5 bytes, not the 16 bytes of an AES-128 key
            $xml = $this->buildEncryptedNameId($keyTransport, random_bytes(5));

            // Control: the data is encrypted with a random key, it can not be decrypted
            $dom = new DOMDocument();
            $dom->loadXML($xml);
            try {
                Utils::decryptElement($dom->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0), $seckey, true, true);
                $this->fail('Exception was not raised');
            } catch (Exception $e) {
                $this->assertEquals('Failure decrypting Data', $e->getMessage());
            }

            // The data is encrypted with the substitute key
            $dom = new DOMDocument();
            $dom->loadXML($xml);
            $xpath = new DOMXPath($dom);
            $xpath->registerNamespace('xenc', XMLSecEnc::XMLENCNS);
            $encryptedData = $dom->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedData')->item(0);

            $encryptedKey = base64_decode($xpath->evaluate('string(.//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue)', $encryptedData));
            $substituteKey = substr(hash_hmac('sha256', $encryptedKey, $seckey->key, true), 0, 16);

            $nameId = new DOMDocument();
            $nameId->loadXML('<saml:NameID xmlns:saml="' . Constants::NS_SAML . '">substitute-key</saml:NameID>');
            $enc = new XMLSecEnc();
            $enc->setNode($nameId->documentElement);
            $enc->type = XMLSecEnc::Element;
            $symmetricKey = new XMLSecurityKey(XMLSecurityKey::AES128_GCM);
            $symmetricKey->loadKey($substituteKey);
            $reencrypted = $enc->encryptNode($symmetricKey);
            $xpath->query('./xenc:CipherData/xenc:CipherValue', $encryptedData)->item(0)->nodeValue
                = $reencrypted->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'CipherValue')->item(0)->nodeValue;

            $decrypted = Utils::decryptElement($encryptedData, $seckey, true, true);
            $this->assertEquals('substitute-key', $decrypted->nodeValue, $keyTransport);
        }
    }

    /**
     * Moves the EncryptedKey out of the KeyInfo of an EncryptedData, next to it, and references
     * it with a RetrievalMethod (the layout that Shibboleth produces)
     *
     * @param string $encryptedDataXml xenc:EncryptedData element
     *
     * @return string xenc:EncryptedData element followed by the xenc:EncryptedKey element
     */
    private function withSiblingEncryptedKey($encryptedDataXml)
    {
        $dom = new DOMDocument();
        $dom->loadXML($encryptedDataXml);

        $encryptedKey = $dom->getElementsByTagNameNS(XMLSecEnc::XMLENCNS, 'EncryptedKey')->item(0);
        $keyInfo = $encryptedKey->parentNode;
        $encryptedKey->setAttribute('Id', '_sibling_key');
        $encryptedKeyXml = $encryptedKey->C14N(); // keeps the namespaces declared by the ancestors
        $keyInfo->removeChild($encryptedKey);

        $retrievalMethod = $dom->createElementNS(XMLSecurityDSig::XMLDSIGNS, 'ds:RetrievalMethod');
        $retrievalMethod->setAttribute('URI', '#_sibling_key');
        $retrievalMethod->setAttribute('Type', 'http://www.w3.org/2001/04/xmlenc#EncryptedKey');
        $keyInfo->appendChild($retrievalMethod);

        $result = $dom->saveXML($dom->documentElement) . $encryptedKeyXml;
        $this->assertStringContainsString('RetrievalMethod', $result);

        return $result;
    }

    /**
     * The EncryptedKey is not inside the KeyInfo of the EncryptedData, it is referenced with a
     * RetrievalMethod
     *
     * @covers OneLogin\Saml2\Response::getNameId
     * @covers OneLogin\Saml2\Response::getAttributes
     */
    public function testEncryptedAssertionWithSiblingEncryptedKey()
    {
        $settingsInfo = $this->settingsInfoWithKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));

        $assertion = '<saml:Assertion xmlns:saml="' . Constants::NS_SAML . '" ID="_assertion" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<saml:Subject><saml:NameID Format="' . Constants::NAMEID_EMAIL_ADDRESS . '">user@example.com</saml:NameID></saml:Subject>'
            . '<saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>jdoe</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>'
            . '</saml:Assertion>';

        $cases = array(
            array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES128_GCM),
            array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::AES128_CBC),
            array(XMLSecurityKey::RSA_OAEP, XMLSecurityKey::AES128_CBC),
            array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::TRIPLEDES_CBC),
            array(XMLSecurityKey::RSA_1_5, XMLSecurityKey::AES128_CBC),
        );
        foreach ($cases as $case) {
            list($keyTransport, $dataAlgorithm) = $case;

            $response = base64_encode(
                '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_response" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
                . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
                . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
                . '<saml:EncryptedAssertion>' . $this->withSiblingEncryptedKey($this->encryptForSP($assertion, $keyTransport, null, false, $dataAlgorithm)) . '</saml:EncryptedAssertion>'
                . '</samlp:Response>'
            );

            // RSA-1.5 has to be enabled
            $settings = $keyTransport === XMLSecurityKey::RSA_1_5 ? $this->createLegacyEncryptionSettings($settingsInfo) : new Settings($settingsInfo);
            $responseObject = new Response($settings, $response);
            $this->assertSame('user@example.com', $responseObject->getNameId(), "$keyTransport, $dataAlgorithm");
            $this->assertSame(array('uid' => array('jdoe')), $responseObject->getAttributes(), "$keyTransport, $dataAlgorithm");
        }

        // The key transport is still checked: RSA-1.5 is rejected by default
        $response = base64_encode(
            '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="_response" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:EncryptedAssertion>' . $this->withSiblingEncryptedKey($this->encryptForSP($assertion, XMLSecurityKey::RSA_1_5)) . '</saml:EncryptedAssertion>'
            . '</samlp:Response>'
        );
        try {
            new Response(new Settings($settingsInfo), $response);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertStringContainsString('RSA-1.5 key transport is disabled', $e->getMessage());
        }
    }

    /**
     * The same layout for the EncryptedID of a LogoutRequest
     *
     * @covers OneLogin\Saml2\Utils::decryptElement
     * @covers OneLogin\Saml2\LogoutRequest::getNameId
     */
    public function testEncryptedIdWithSiblingEncryptedKey()
    {
        $key = file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key');
        $nameId = '<saml:NameID xmlns:saml="' . Constants::NS_SAML . '">user@example.com</saml:NameID>';

        foreach (array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_OAEP, XMLSecurityKey::RSA_1_5) as $keyTransport) {
            $encryptedId = '<saml:EncryptedID xmlns:saml="' . Constants::NS_SAML . '">'
                . $this->withSiblingEncryptedKey($this->encryptForSP($nameId, $keyTransport))
                . '</saml:EncryptedID>';
            $logoutRequest = $this->buildLogoutRequestWithEncryptedId($encryptedId);

            $this->assertSame('user@example.com', LogoutRequest::getNameId($logoutRequest, $key, true), $keyTransport);
        }
    }
}
