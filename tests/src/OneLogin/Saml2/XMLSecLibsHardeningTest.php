<?php

/**
 * Unit tests for the checks done before the bundled xmlseclibs processes
 * received Signatures and encrypted elements. Each test reproduces an attack of
 * the xmlseclibs advisories published in August 2026 (fixed in xmlseclibs 4.x,
 * that requires PHP 8).
 */
class OneLogin_Saml2_XMLSecLibsHardeningTest extends PHPUnit_Framework_TestCase
{
    const RESPONSE_ID = 'pfxc3d2b542-0f7e-8767-8e87-5b0dc6913375';

    const ASSERTION = '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_forged_assertion" Version="2.0" IssueInstant="2014-03-29T12:01:57Z"><saml:Issuer>http://idp.example.com/</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">forged-nameid</saml:NameID></saml:Subject></saml:Assertion>';

    private $_settingsInfo;

    /**
    * Initializes the Test Suite
    */
    public function setUp()
    {
        $settingsDir = TEST_ROOT .'/settings/';
        include $settingsDir.'settings1.php';

        $this->_settingsInfo = $settingsInfo;
        unset($_SERVER['QUERY_STRING']);
    }

    /**
     * Tests that the new setting keeps accepting rsa-1_5 by default.
     *
     * @covers OneLogin_Saml2_Settings::getSecurityData
     */
    public function testEncryptionAlgorithmSettingsDefaults()
    {
        $security = $this->getSettings()->getSecurityData();
        $this->assertTrue($security['allowRSA15KeyTransport']);

        $security = $this->getSettings(array('allowRSA15KeyTransport' => false))->getSecurityData();
        $this->assertFalse($security['allowRSA15KeyTransport']);
    }

    /**
     * GHSA-7mf5-fjj8-mvjc: xmlseclibs evaluates the XPath of an XPath Transform
     * before any cryptographic check (pre-authentication CPU DoS). Transforms
     * not used by SAML are rejected before reaching xmlseclibs.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Utils::validateSignatureStructure
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testXPathTransformIsRejected()
    {
        // ~3 seconds of CPU per request on xmlseclibs 3.x, one more level is ~25 times more
        $expensiveXPath = 'count(//*[count(//*[count(//*[count(//*) > 0]) > 0]) > 0]) > 0';
        $transforms = array(
            '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>'.$expensiveXPath.'</ds:XPath></ds:Transform>',
            '<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2"><dsig-xpath:XPath xmlns:dsig-xpath="http://www.w3.org/2002/06/xmldsig-filter2" Filter="intersect">'.$expensiveXPath.'</dsig-xpath:XPath></ds:Transform>',
            '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>',
        );

        foreach ($transforms as $transform) {
            $xml = str_replace('<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', $transform, $this->getSignedResponse());
            $this->assertContains($transform, $xml);

            $this->assertSignatureRejected($xml, 'Unsupported Transform in the Signature');

            $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
            $this->assertFalse($response->isValid());
            $this->assertEquals('Unsupported Transform in the Signature', $response->getError());
        }
    }

    /**
     * GHSA-m5mw-mr39-66vp, GHSA-w5f2-cpgp-pg76 and GHSA-cw72-f8pq-h4pg: the
     * SignatureMethod is switched to hmac-sha1 and the HMAC is computed with the
     * public certificate of the IdP (PEM and DER) as secret. Only RSA signature
     * algorithms are accepted, so the HMAC code of xmlseclibs is never reached.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testHmacSignatureForgeryIsRejected()
    {
        $cert = $this->_settingsInfo['idp']['x509cert'];
        $secrets = array(
            'PEM' => OneLogin_Saml2_Utils::formatCert($cert),
            'DER' => base64_decode($cert),
        );

        foreach ($secrets as $secret) {
            $xml = $this->forgeHmacSignature($this->getSignedResponse(), $secret);

            $this->assertSignatureRejected($xml, 'Unsupported signing algorithm.');

            $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
            $this->assertFalse($response->isValid());
            $this->assertEquals('Unsupported signing algorithm.', $response->getError());
        }
    }

    /**
     * Same downgrade on the HTTP-Redirect binding. With several IdP signing
     * certificates an unsupported SigAlg was ignored and the signature was
     * checked as rsa-sha1, now it is always rejected.
     *
     * @covers OneLogin_Saml2_Utils::validateBinarySign
     */
    public function testHmacSigAlgIsRejectedOnRedirectBinding()
    {
        foreach (array('settings1.php', 'settings6.php') as $settingsFile) {
            include TEST_ROOT .'/settings/'.$settingsFile;
            $settings = new OneLogin_Saml2_Settings($settingsInfo);
            $idpData = $settings->getIdPData();
            if (isset($idpData['x509certMulti']['signing'])) {
                $cert = $idpData['x509certMulti']['signing'][0];
            } else {
                $cert = $idpData['x509cert'];
            }

            $getData = array(
                'SAMLRequest' => base64_encode(gzdeflate('<samlp:LogoutRequest/>')),
                'RelayState' => 'http://sp.example.com/',
                'SigAlg' => XMLSecurityKey::HMAC_SHA1,
            );
            $signedQuery = 'SAMLRequest='.urlencode($getData['SAMLRequest']).'&RelayState='.urlencode($getData['RelayState']).'&SigAlg='.urlencode($getData['SigAlg']);
            $getData['Signature'] = base64_encode(hash_hmac('sha1', $signedQuery, OneLogin_Saml2_Utils::formatCert($cert), true));

            try {
                OneLogin_Saml2_Utils::validateBinarySign('SAMLRequest', $getData, $idpData);
                $this->fail('OneLogin_Saml2_ValidationError was not raised');
            } catch (OneLogin_Saml2_ValidationError $e) {
                $this->assertEquals('Invalid signAlg in the received Logout Request', $e->getMessage());
                $this->assertEquals(OneLogin_Saml2_ValidationError::INVALID_SIGNATURE, $e->getCode());
            }
        }
    }

    /**
     * GHSA-9wcx-p7hr-f935: with a DOCTYPE, an ID="&entity;" attribute is seen by
     * getAttribute() but not by the XPath lookup of xmlseclibs, so the signature
     * can be checked on a different node. XML strings with a DOCTYPE were already
     * rejected by OneLogin_Saml2_Utils::loadXML, now DOMDocuments passed to
     * validateSign are too.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Utils::validateSignatureStructure
     * @covers OneLogin_Saml2_Utils::validateEncryptedDataStructure
     */
    public function testDoctypeIsRejected()
    {
        $doctypeMessage = 'Detected use of DOCTYPE/ENTITY in XML, disabled to prevent XXE/XEE attacks';

        $xml = '<!DOCTYPE samlp:Response [<!ENTITY id "'.self::RESPONSE_ID.'">]>'
            .str_replace('ID="'.self::RESPONSE_ID.'"', 'ID="&id;"', $this->getSignedResponse());
        $dom = new DOMDocument();
        $dom->loadXML($xml);
        $this->assertSignatureRejected($dom, $doctypeMessage);

        try {
            new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertEquals($doctypeMessage, $e->getMessage());
        }

        list($cipherValue, $keyCipherValue) = $this->encryptForSP(self::ASSERTION, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
        $encryptedData = $this->buildEncryptedData(
            XMLSecurityKey::AES128_CBC,
            $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, $keyCipherValue),
            $cipherValue
        );
        $dom = new DOMDocument();
        $dom->loadXML('<!DOCTYPE saml:EncryptedID []><saml:EncryptedID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">'.$encryptedData.'</saml:EncryptedID>');
        try {
            OneLogin_Saml2_Utils::decryptElement($dom->getElementsByTagNameNS(OneLogin_Saml2_Constants::NS_XENC, 'EncryptedData')->item(0), $this->getSPKey());
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertEquals($doctypeMessage, $e->getMessage());
            $this->assertEquals(OneLogin_Saml2_ValidationError::INVALID_XML_FORMAT, $e->getCode());
        }
    }

    /**
     * xmlseclibs 3.x digests the first element whose ID matches the Reference URI
     * and accepts URIs that are not same-document references (fail closed in
     * xmlseclibs 4.0.0). The Reference must identify exactly one element.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Utils::validateSignatureStructure
     */
    public function testReferenceMustIdentifyExactlyOneElement()
    {
        $signed = $this->getSignedResponse();

        foreach (array('ID', 'Id') as $attribute) {
            $xml = str_replace('<samlp:Status>', '<samlp:Extensions><x:Wrapper xmlns:x="urn:x" '.$attribute.'="'.self::RESPONSE_ID.'"/></samlp:Extensions><samlp:Status>', $signed);
            $this->assertSignatureRejected($xml, 'Reference URI must identify exactly one element');
        }

        $xml = str_replace('URI="#'.self::RESPONSE_ID.'"', 'URI="#unknown"', $signed);
        $this->assertSignatureRejected($xml, 'Reference URI must identify exactly one element');

        foreach (array('http://attacker.example.com/doc.xml#'.self::RESPONSE_ID, 'doc.xml#'.self::RESPONSE_ID, '#') as $uri) {
            $xml = str_replace('URI="#'.self::RESPONSE_ID.'"', 'URI="'.$uri.'"', $signed);
            $this->assertSignatureRejected($xml, 'Reference URI must point to an element of the same document');
        }
    }

    /**
     * xmlseclibs 3.x uses the first element when SignedInfo children are
     * duplicated and falls back to inclusive c14n with an unknown
     * CanonicalizationMethod (rejected in xmlseclibs 4.0.0).
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Utils::validateSignatureStructure
     */
    public function testSignatureStructureIsChecked()
    {
        $signed = $this->getSignedResponse();
        preg_match('#<ds:SignatureValue>.*?</ds:SignatureValue>#s', $signed, $signatureValue);
        preg_match('#<ds:Reference .*?</ds:Reference>#s', $signed, $reference);
        $signatureMethod = '<ds:SignatureMethod Algorithm="'.XMLSecurityKey::RSA_SHA1.'"/>';
        $canonicalizationMethod = '<ds:CanonicalizationMethod Algorithm="'.XMLSecurityDSig::EXC_C14N.'"/>';

        $this->assertSignatureRejected(
            str_replace($signatureValue[0], $signatureValue[0].$signatureValue[0], $signed),
            'Invalid Signature structure'
        );
        $this->assertSignatureRejected(
            str_replace($reference[0], $reference[0].$reference[0], $signed),
            'Unexpected number of Reference nodes found for signature'
        );
        $this->assertSignatureRejected(
            str_replace('<ds:DigestValue>', '<ds:DigestValue>AAAA</ds:DigestValue><ds:DigestValue>', $signed),
            'Invalid Reference structure in the Signature'
        );
        $this->assertSignatureRejected(
            str_replace($signatureMethod, $signatureMethod.'<ds:SignatureMethod Algorithm="'.XMLSecurityKey::HMAC_SHA1.'"/>', $signed),
            'Unsupported signing algorithm.'
        );
        $this->assertSignatureRejected(
            str_replace($canonicalizationMethod, '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>', $signed),
            'Unsupported CanonicalizationMethod in the Signature'
        );
    }

    /**
     * GHSA-39hg-wfcm-v4wv: with allowRSA15KeyTransport set to false, rsa-1_5 is
     * rejected before decrypting, so the Bleichenbacher oracle can not be
     * reached. RSA-OAEP keeps working. The bundled xmlseclibs only supports CBC
     * for the data, so there is no authenticated alternative to it.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_Utils::validateEncryptedDataStructure
     */
    public function testRSA15KeyTransportCanBeDisabled()
    {
        $noRSA15 = $this->getSettings(array('allowRSA15KeyTransport' => false));

        // rsa-1_5 + aes128-cbc, accepted by default
        $legacy = $this->getEncryptedResponse();
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($legacy));
        $this->assertTrue($response->encrypted);

        $this->assertResponseRejected($legacy, $noRSA15, OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, 'Unsupported or not allowed key transport algorithm');

        $xml = $this->buildEncryptedResponse(self::ASSERTION, XMLSecurityKey::AES256_CBC, XMLSecurityKey::RSA_1_5);
        $this->assertResponseRejected($xml, $noRSA15, OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, 'Unsupported or not allowed key transport algorithm');

        $dataAlgorithms = array(XMLSecurityKey::AES128_CBC, XMLSecurityKey::AES192_CBC, XMLSecurityKey::AES256_CBC, XMLSecurityKey::TRIPLEDES_CBC);
        foreach ($dataAlgorithms as $dataAlgorithm) {
            $xml = $this->buildEncryptedResponse(self::ASSERTION, $dataAlgorithm, XMLSecurityKey::RSA_OAEP_MGF1P);
            $response = new OneLogin_Saml2_Response($noRSA15, base64_encode($xml));
            $this->assertEquals('forged-nameid', $response->getNameId(), $dataAlgorithm);
        }

        // Algorithms that the bundled xmlseclibs does not support
        $xml = $this->buildResponse(
            $this->buildEncryptedData('http://www.w3.org/2009/xmlenc11#aes128-gcm', $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, 'AAAA'), 'AAAA')
        );
        $this->assertResponseRejected($xml, $this->getSettings(), OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, 'Unsupported or not allowed data encryption algorithm');
    }

    /**
     * The allowRSA15KeyTransport setting also applies to the EncryptedID of an Assertion.
     *
     * @covers OneLogin_Saml2_Response::getNameIdData
     * @covers OneLogin_Saml2_Utils::decryptElement
     */
    public function testRSA15KeyTransportCanBeDisabledOnEncryptedNameId()
    {
        // EncryptedID with rsa-1_5 + aes128-cbc
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/response_encrypted_nameid.xml.base64'));
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
        $this->assertNotEmpty($response->getNameId());

        $response = new OneLogin_Saml2_Response($this->getSettings(array('allowRSA15KeyTransport' => false)), base64_encode($xml));
        try {
            $response->getNameId();
            $this->fail('OneLogin_Saml2_ValidationError was not raised');
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertEquals('Unsupported or not allowed key transport algorithm', $e->getMessage());
            $this->assertEquals(OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, $e->getCode());
        }
    }

    /**
     * The EncryptedID of the Subject of an EncryptedAssertion is decrypted
     * (it failed on PHP 5 because of a scalar type declaration), and the
     * allowRSA15KeyTransport setting applies to it.
     *
     * @covers OneLogin_Saml2_Response::__construct
     */
    public function testEncryptedNameIdInEncryptedAssertion()
    {
        $nameIdXml = '<saml:NameID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">subject-nameid</saml:NameID>';
        foreach (array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_1_5) as $keyAlgorithm) {
            list($idCipherValue, $idKeyCipherValue) = $this->encryptForSP($nameIdXml, XMLSecurityKey::AES128_CBC, $keyAlgorithm);
            $encryptedId = '<saml:EncryptedID>'.$this->buildEncryptedData(
                XMLSecurityKey::AES128_CBC,
                $this->buildEncryptedKey($keyAlgorithm, $idKeyCipherValue),
                $idCipherValue
            ).'</saml:EncryptedID>';
            $assertion = preg_replace('#<saml:NameID .*</saml:NameID>#', $encryptedId, self::ASSERTION);
            $xml = $this->buildEncryptedResponse($assertion, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);

            $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
            $this->assertTrue($response->encryptedNameId);
            $this->assertSame('subject-nameid', $response->getNameId());

            if ($keyAlgorithm === XMLSecurityKey::RSA_1_5) {
                $this->assertResponseRejected($xml, $this->getSettings(array('allowRSA15KeyTransport' => false)), OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, 'Unsupported or not allowed key transport algorithm');
            }
        }
    }

    /**
     * The plaintext of the EncryptedAssertion may not declare the saml namespace (the
     * Response does), with the EncryptedID declaring it or not. The EncryptedID is then
     * read by getNameId() instead of being decrypted with the Assertion, so the
     * allowRSA15KeyTransport setting must still apply to it.
     *
     * @covers OneLogin_Saml2_Response::getNameId
     */
    public function testEncryptedNameIdInEncryptedAssertionWithoutNamespaceDeclarations()
    {
        foreach (array(true, false) as $declareNamespaceInId) {
            foreach (array(XMLSecurityKey::RSA_OAEP_MGF1P, XMLSecurityKey::RSA_1_5) as $keyAlgorithm) {
                $name = $keyAlgorithm.($declareNamespaceInId ? ' (EncryptedID declares the namespace)' : '');
                $xml = base64_encode($this->buildResponseWithoutNamespaceDeclarations($keyAlgorithm, true, $declareNamespaceInId));

                $response = new OneLogin_Saml2_Response($this->getSettings(), $xml);
                $this->assertSame('subject-nameid', $response->getNameId(), $name);

                if ($keyAlgorithm === XMLSecurityKey::RSA_1_5) {
                    // The EncryptedAssertion is accepted, the EncryptedID is rejected when it is read
                    $response = new OneLogin_Saml2_Response($this->getSettings(array('allowRSA15KeyTransport' => false)), $xml);
                    try {
                        $response->getNameId();
                        $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$name);
                    } catch (OneLogin_Saml2_ValidationError $e) {
                        $this->assertEquals('Unsupported or not allowed key transport algorithm', $e->getMessage(), $name);
                        $this->assertEquals(OneLogin_Saml2_ValidationError::KEY_ALGORITHM_ERROR, $e->getCode(), $name);
                    }
                }
            }
        }
    }

    /**
     * With the EncryptedID read by getNameId() (see the previous test), 'wantNameIdEncrypted'
     * is still satisfied by the NameID of the Subject, and still rejects a NameID that
     * is not encrypted. Both are checked in strict mode before the Conditions.
     *
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testWantNameIdEncryptedWithoutNamespaceDeclarations()
    {
        $settings = $this->getSettings(array('wantNameIdEncrypted' => true, 'wantXMLValidation' => false), true);

        foreach (array(true, false) as $declareNamespaceInId) {
            $xml = $this->buildResponseWithoutNamespaceDeclarations(XMLSecurityKey::RSA_OAEP_MGF1P, true, $declareNamespaceInId);
            $response = new OneLogin_Saml2_Response($settings, base64_encode($xml));
            $this->assertFalse($response->isValid());
            $this->assertSame('The Assertion must include a Conditions element', $response->getError(), 'EncryptedID declares the namespace: '.var_export($declareNamespaceInId, true));
            $this->assertTrue($response->encryptedNameId);
        }

        $xml = $this->buildResponseWithoutNamespaceDeclarations(XMLSecurityKey::RSA_OAEP_MGF1P, false);
        $response = new OneLogin_Saml2_Response($settings, base64_encode($xml));
        $this->assertFalse($response->isValid());
        $this->assertSame('The NameID of the Response is not encrypted and the SP requires it', $response->getError());
        $this->assertFalse($response->encryptedNameId);
    }

    /**
     * GHSA-39hg-wfcm-v4wv and GHSA-7h47-29x2-r2gc: every failure that depends on
     * the decrypted bytes is reported with the same error, so a padding error
     * can not be told apart from other failures.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_Utils::decryptSymmetricKey
     */
    public function testDecryptionFailuresAreIndistinguishable()
    {
        $xml = $this->getEncryptedResponse();
        preg_match_all('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $xml, $matches);
        $keyCipherValue = $matches[1][0];
        $cipherValue = $matches[1][1];

        $attacks = array(
            'rsa-1_5 key of random bytes' => str_replace($keyCipherValue, base64_encode($this->randomBytes(128)), $xml),
            'rsa-1_5 key of 5 bytes' => str_replace($keyCipherValue, base64_encode($this->randomBytes(5)), $xml),
            'cbc last byte modified' => str_replace($cipherValue, $this->flipByte($cipherValue, -1), $xml),
            'cbc first block modified' => str_replace($cipherValue, $this->flipByte($cipherValue, 20), $xml),
            'cbc random data' => str_replace($cipherValue, base64_encode($this->randomBytes(strlen(base64_decode($cipherValue)))), $xml),
            'data algorithm changed' => str_replace('xmlenc#aes128-cbc', 'xmlenc#aes256-cbc', $xml),
            'plaintext is not xml' => $this->buildEncryptedResponse('not xml', XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P),
            'plaintext is empty' => $this->buildEncryptedResponse('', XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P),
        );
        foreach ($attacks as $name => $attack) {
            $this->assertResponseRejected($attack, $this->getSettings(), OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $name);
        }
    }

    /**
     * Same as testDecryptionFailuresAreIndistinguishable for the EncryptedID of a
     * LogoutRequest (OneLogin_Saml2_Utils::decryptElement).
     *
     * @covers OneLogin_Saml2_LogoutRequest::getNameIdData
     * @covers OneLogin_Saml2_Utils::decryptElement
     */
    public function testEncryptedIdDecryptionFailuresAreIndistinguishable()
    {
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');
        $key = $this->getSettings()->getSPkey();
        $this->assertNotEmpty(OneLogin_Saml2_LogoutRequest::getNameId($request, $key));

        preg_match_all('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $request, $matches);
        $keyCipherValue = $matches[1][0];
        $cipherValue = $matches[1][1];

        $attacks = array(
            'rsa-1_5 key of random bytes' => str_replace($keyCipherValue, base64_encode($this->randomBytes(128)), $request),
            'cbc last byte modified' => str_replace($cipherValue, $this->flipByte($cipherValue, -1), $request),
            'data algorithm changed' => str_replace('xmlenc#aes128-cbc', 'xmlenc#aes256-cbc', $request),
        );
        foreach ($attacks as $name => $attack) {
            try {
                OneLogin_Saml2_LogoutRequest::getNameIdData($attack, $key);
                $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$name);
            } catch (OneLogin_Saml2_ValidationError $e) {
                $this->assertEquals(OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $e->getMessage(), $name);
                $this->assertEquals(OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, $e->getCode(), $name);
            }
        }
    }

    /**
     * The decrypted content of an EncryptedID must be an element. Anyone can
     * encrypt text for the SP, and the text node returned as the NameID made
     * OneLogin_Saml2_LogoutRequest::getNameIdData fail with a fatal error
     * instead of a OneLogin_Saml2_ValidationError.
     *
     * @covers OneLogin_Saml2_Utils::decryptElement
     * @covers OneLogin_Saml2_LogoutRequest::getNameIdData
     */
    public function testDecryptedContentMustBeAnElement()
    {
        foreach (array('just-text', '<!-- only a comment -->') as $plaintext) {
            list($cipherValue, $keyCipherValue) = $this->encryptForSP($plaintext, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
            $encryptedId = '<saml:EncryptedID>'.$this->buildEncryptedData(
                XMLSecurityKey::AES128_CBC,
                $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, $keyCipherValue),
                $cipherValue
            ).'</saml:EncryptedID>';
            $request = '<samlp:LogoutRequest xmlns:samlp="'.OneLogin_Saml2_Constants::NS_SAMLP.'" xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'" ID="_logout" Version="2.0" IssueInstant="2014-03-29T12:01:57Z"><saml:Issuer>http://idp.example.com/</saml:Issuer>'.$encryptedId.'</samlp:LogoutRequest>';
            try {
                OneLogin_Saml2_LogoutRequest::getNameIdData($request, $this->getSettings()->getSPkey());
                $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$plaintext);
            } catch (OneLogin_Saml2_ValidationError $e) {
                $this->assertEquals(OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $e->getMessage(), $plaintext);
                $this->assertEquals(OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, $e->getCode(), $plaintext);
            }
        }
    }

    /**
     * GHSA-39hg-wfcm-v4wv: Bleichenbacher queries are RSA ciphertexts whose
     * PKCS#1 v1.5 structure the attacker chooses. decryptSymmetricKey returns a
     * key of the expected size for all of them, without exceptions and without
     * leaving OpenSSL errors: when the RSA decryption fails (as OpenSSL < 3.2
     * does for a padding error, and any OpenSSL for a ciphertext bigger than the
     * modulus), when the decrypted key has another size, and when it is valid.
     *
     * @covers OneLogin_Saml2_Utils::decryptSymmetricKey
     */
    public function testDecryptSymmetricKeyHidesRSAFailures()
    {
        $blocks = $this->getPKCS1Blocks();
        $ciphertexts = $this->getRSA15Ciphertexts($blocks);
        foreach ($ciphertexts as $name => $ciphertext) {
            $key = $this->decryptSymmetricKey($ciphertext, 16);
            $this->assertSame(16, strlen($key), $name);
            $this->assertFalse(openssl_error_string(), $name);
            $this->assertSame($key, $this->decryptSymmetricKey($ciphertext, 16), $name);
        }

        $this->assertSame(
            substr($blocks['conformant, key of 16 bytes']['block'], -16),
            $this->decryptSymmetricKey($ciphertexts['conformant, key of 16 bytes'], 16)
        );
        $this->assertNotSame(
            $this->decryptSymmetricKey($ciphertexts['rsa decryption error'], 16),
            $this->decryptSymmetricKey($ciphertexts['conformant, key of 5 bytes'], 16)
        );
    }

    /**
     * decryptSymmetricKey uses the padding of the key transport algorithm of
     * the EncryptedKey (RSA-OAEP and RSA-1.5), and a ciphertext that does not
     * match it gets the replacement key.
     *
     * @covers OneLogin_Saml2_Utils::decryptSymmetricKey
     */
    public function testDecryptSymmetricKeyWithOAEP()
    {
        $publicKey = openssl_pkey_get_public($this->getSettings()->getSPcert());
        $symmetricKey = $this->randomBytes(32);
        openssl_public_encrypt($symmetricKey, $oaepCiphertext, $publicKey, OPENSSL_PKCS1_OAEP_PADDING);
        openssl_public_encrypt($symmetricKey, $pkcs1Ciphertext, $publicKey, OPENSSL_PKCS1_PADDING);

        $this->assertSame($symmetricKey, $this->decryptSymmetricKey($oaepCiphertext, 32, XMLSecurityKey::RSA_OAEP_MGF1P));
        $this->assertSame($symmetricKey, $this->decryptSymmetricKey($pkcs1Ciphertext, 32, XMLSecurityKey::RSA_1_5));

        $replacementKey = $this->decryptSymmetricKey($pkcs1Ciphertext, 32, XMLSecurityKey::RSA_OAEP_MGF1P);
        $this->assertSame(32, strlen($replacementKey));
        $this->assertNotSame($symmetricKey, $replacementKey);
        $this->assertFalse(openssl_error_string());
    }

    /**
     * The EncryptedID of a LogoutRequest is decrypted after the signature of
     * the HTTP-Redirect binding is verified (tampered ciphertexts do not reach
     * the decryption code), and the allowRSA15KeyTransport setting applies to it.
     *
     * @covers OneLogin_Saml2_LogoutRequest::isValid
     */
    public function testLogoutRequestNameIdIsDecryptedAfterTheSignature()
    {
        // EncryptedID with rsa-1_5 + aes128-cbc
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');
        $request = preg_replace('/ Destination="[^"]*"/', '', $request);
        $request = str_replace('http://stuff.com/endpoints/metadata.php', $this->_settingsInfo['idp']['entityId'], $request);
        preg_match('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $request, $match);
        $tampered = str_replace($match[1], base64_encode($this->randomBytes(128)), $request);

        $this->assertSame(array(true, null), $this->validateLogoutRequest($request, array()));
        $this->assertSame(
            array(false, 'Unsupported or not allowed key transport algorithm'),
            $this->validateLogoutRequest($request, array('allowRSA15KeyTransport' => false))
        );

        $this->assertSame(
            array(false, 'Signature validation failed. Logout Request rejected'),
            $this->validateLogoutRequest($tampered, array(), 'invalid')
        );
        $this->assertSame(
            array(false, 'The Message of the Logout Request is not signed and the SP require it'),
            $this->validateLogoutRequest($tampered, array(), 'none')
        );
        // Signed by the IdP, so it is decrypted (and fails with the generic error)
        $this->assertSame(
            array(false, OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE),
            $this->validateLogoutRequest($tampered, array())
        );
    }

    /**
     * GHSA-39hg-wfcm-v4wv: Bleichenbacher queries in a Response and in the
     * EncryptedID of a LogoutRequest are all reported with the same error,
     * whatever the OpenSSL version.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_LogoutRequest::getNameIdData
     */
    public function testRSA15PaddingOracleIsNotExposed()
    {
        $xml = $this->getEncryptedResponse();
        preg_match('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $xml, $match);
        $request = file_get_contents(TEST_ROOT . '/data/logout_requests/logout_request_encrypted_nameid.xml');
        preg_match('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $request, $requestMatch);

        foreach ($this->getRSA15Ciphertexts($this->getPKCS1Blocks()) as $name => $ciphertext) {
            $attack = str_replace($match[1], base64_encode($ciphertext), $xml);
            $this->assertResponseRejected($attack, $this->getSettings(), OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $name);
            $this->assertFalse(openssl_error_string(), $name);

            $attack = str_replace($requestMatch[1], base64_encode($ciphertext), $request);
            try {
                OneLogin_Saml2_LogoutRequest::getNameIdData($attack, $this->getSettings()->getSPkey());
                $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$name);
            } catch (OneLogin_Saml2_ValidationError $e) {
                $this->assertEquals(OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $e->getMessage(), $name);
                $this->assertEquals(OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, $e->getCode(), $name);
            }
            $this->assertFalse(openssl_error_string(), $name);
        }
    }

    /**
     * GHSA-39hg-wfcm-v4wv with an OpenSSL without implicit rejection (< 3.2, as
     * on the GitHub CI): OpenSSL fails on not conformant PKCS#1 v1.5 blocks and
     * xmlseclibs raises "Failure decrypting Data" only for them, which is the
     * Bleichenbacher oracle. The toolkit reports conformant and not conformant
     * blocks the same way.
     *
     * OpenSSL 3.2+ never reports PKCS#1 v1.5 padding errors (implicit
     * rejection), so this test is skipped there.
     *
     * @covers OneLogin_Saml2_Utils::decryptSymmetricKey
     * @covers OneLogin_Saml2_Response::__construct
     */
    public function testRSA15PaddingErrorsAreNotExposedWithoutImplicitRejection()
    {
        $privateKey = openssl_pkey_get_private($this->getSettings()->getSPkey());
        $blocks = $this->getPKCS1Blocks();
        $probe = $this->rawRSAEncryptForSP($blocks['not conformant, 00 03 prefix']['block']);
        $explicitRejection = openssl_private_decrypt($probe, $decrypted, $privateKey, OPENSSL_PKCS1_PADDING) === false;
        while (openssl_error_string() !== false);
        if (!$explicitRejection) {
            $this->markTestSkipped(OPENSSL_VERSION_TEXT.' uses implicit rejection for PKCS#1 v1.5 (OpenSSL 3.2+), this test needs an OpenSSL that reports padding errors');
        }

        $xml = $this->getEncryptedResponse();
        preg_match('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $xml, $match);

        foreach ($blocks as $name => $block) {
            $ciphertext = $this->rawRSAEncryptForSP($block['block']);

            // OpenSSL tells conformant and not conformant blocks apart
            $this->assertSame($block['conformant'], openssl_private_decrypt($ciphertext, $decrypted, $privateKey, OPENSSL_PKCS1_PADDING) !== false, $name);
            while (openssl_error_string() !== false);

            // and xmlseclibs raises an exception only for the not conformant ones
            if (!$block['conformant']) {
                $dom = new DOMDocument();
                $dom->loadXML($this->buildEncryptedKey(XMLSecurityKey::RSA_1_5, base64_encode($ciphertext)));
                $keyInfo = XMLSecurityKey::fromEncryptedKeyElement($dom->documentElement);
                $keyInfo->loadKey($this->getSettings()->getSPkey());
                try {
                    $keyInfo->encryptedCtx->decryptKey($keyInfo);
                    $this->fail('Exception was not raised: '.$name);
                } catch (Exception $e) {
                    $this->assertStringStartsWith('Failure decrypting Data', $e->getMessage(), $name);
                }
                while (openssl_error_string() !== false);
            }

            // the toolkit does not
            $this->assertSame(16, strlen($this->decryptSymmetricKey($ciphertext, 16)), $name);
            $this->assertFalse(openssl_error_string(), $name);
            $attack = str_replace($match[1], base64_encode($ciphertext), $xml);
            $this->assertResponseRejected($attack, $this->getSettings(), OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $name);
        }
    }

    /**
     * GHSA-7hf8-fh6v-wmm6: decrypted content with a DOCTYPE (XXE / entity
     * expansion) is rejected, for EncryptedAssertion and for EncryptedID. Anyone
     * can encrypt for the SP with the certificate published in its metadata.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_Utils::decryptElement
     */
    public function testDoctypeInDecryptedContentIsRejected()
    {
        $secretFile = tempnam(sys_get_temp_dir(), 'saml');
        file_put_contents($secretFile, 'secret-file-content');
        $doctype = '<!DOCTYPE saml:Assertion [<!ENTITY xxe SYSTEM "file://'.$secretFile.'">]>';

        $plaintext = $doctype.str_replace('forged-nameid', '&xxe;', self::ASSERTION);
        $xml = $this->buildEncryptedResponse($plaintext, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
        try {
            new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
            $assertionError = null;
        } catch (OneLogin_Saml2_ValidationError $e) {
            $assertionError = $e;
        }

        $plaintext = $doctype.'<saml:NameID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">&xxe;</saml:NameID>';
        list($cipherValue, $keyCipherValue) = $this->encryptForSP($plaintext, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
        $encryptedData = $this->buildEncryptedData(
            XMLSecurityKey::AES128_CBC,
            $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, $keyCipherValue),
            $cipherValue
        );
        $dom = new DOMDocument();
        $dom->loadXML('<saml:EncryptedID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">'.$encryptedData.'</saml:EncryptedID>');
        try {
            OneLogin_Saml2_Utils::decryptElement($dom->getElementsByTagNameNS(OneLogin_Saml2_Constants::NS_XENC, 'EncryptedData')->item(0), $this->getSPKey());
            $nameIdError = null;
        } catch (OneLogin_Saml2_ValidationError $e) {
            $nameIdError = $e;
        }
        unlink($secretFile);

        foreach (array($assertionError, $nameIdError) as $error) {
            $this->assertInstanceOf('OneLogin_Saml2_ValidationError', $error);
            $this->assertEquals(OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $error->getMessage());
            $this->assertEquals(OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, $error->getCode());
        }
    }

    /**
     * xmlseclibs 3.x resolves RetrievalMethod / EncryptedKey references without
     * a depth limit: a reference loop exhausts the memory and kills the PHP
     * process (pre-authentication DoS, fixed in xmlseclibs 4.0.0). Nested
     * references are rejected before decrypting.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_LogoutRequest::getNameIdData
     * @covers OneLogin_Saml2_Utils::validateEncryptedDataStructure
     */
    public function testEncryptedKeyReferenceLoopsAreRejected()
    {
        $oaep = XMLSecurityKey::RSA_OAEP_MGF1P;
        list($cipherValue, $keyCipherValue) = $this->encryptForSP(self::ASSERTION, XMLSecurityKey::AES128_CBC, $oaep);
        $retrievalMethod = function ($id) {
            return '<ds:RetrievalMethod xmlns:ds="'.OneLogin_Saml2_Constants::NS_DS.'" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#'.$id.'"/>';
        };
        // xmlseclibs follows a RetrievalMethod in any namespace
        $foreignRetrievalMethod = function ($id) {
            return '<r:RetrievalMethod xmlns:r="urn:other" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#'.$id.'"/>';
        };
        $encryptedData = $this->buildEncryptedData(XMLSecurityKey::AES128_CBC, $retrievalMethod('k1'), $cipherValue);

        $attacks = array(
            'self reference' => $encryptedData
                .$this->buildEncryptedKey($oaep, $keyCipherValue, 'k1', $retrievalMethod('k1')),
            'self reference, RetrievalMethod in another namespace' => $this->buildEncryptedData(XMLSecurityKey::AES128_CBC, $foreignRetrievalMethod('k1'), $cipherValue)
                .$this->buildEncryptedKey($oaep, $keyCipherValue, 'k1', $foreignRetrievalMethod('k1')),
            'reference cycle' => $encryptedData
                .$this->buildEncryptedKey($oaep, $keyCipherValue, 'k1', $retrievalMethod('k2'))
                .$this->buildEncryptedKey($oaep, $keyCipherValue, 'k2', $retrievalMethod('k1')),
            'nested EncryptedKey' => $this->buildEncryptedData(
                XMLSecurityKey::AES128_CBC,
                $this->buildEncryptedKey($oaep, $keyCipherValue, null, $this->buildEncryptedKey($oaep, $keyCipherValue)),
                $cipherValue
            ),
        );
        foreach ($attacks as $name => $attack) {
            $this->assertResponseRejected($this->buildResponse($attack), $this->getSettings(), OneLogin_Saml2_ValidationError::UNSUPPORTED_RETRIEVAL_METHOD, 'Nested EncryptedKey references are not supported', $name);

            $request = '<samlp:LogoutRequest xmlns:samlp="'.OneLogin_Saml2_Constants::NS_SAMLP.'" xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'" ID="_logout" Version="2.0" IssueInstant="2014-03-29T12:01:57Z"><saml:Issuer>http://idp.example.com/</saml:Issuer><saml:EncryptedID>'.$attack.'</saml:EncryptedID></samlp:LogoutRequest>';
            try {
                OneLogin_Saml2_LogoutRequest::getNameIdData($request, $this->getSettings()->getSPkey());
                $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$name);
            } catch (OneLogin_Saml2_ValidationError $e) {
                $this->assertEquals(OneLogin_Saml2_ValidationError::UNSUPPORTED_RETRIEVAL_METHOD, $e->getCode(), $name);
            }
        }

        // A RetrievalMethod to an EncryptedKey that is a sibling of the EncryptedData is still supported
        $xml = $this->buildResponse($encryptedData.$this->buildEncryptedKey($oaep, $keyCipherValue, 'k1'));
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
        $this->assertEquals('forged-nameid', $response->getNameId());
    }

    /**
     * Only the EncryptedData of the EncryptedAssertion of the Response is
     * decrypted (xmlseclibs locateEncryptedData returns the first one of the
     * document), and only the EncryptedID of the Subject of the Assertion.
     *
     * @covers OneLogin_Saml2_Response::__construct
     */
    public function testOnlyTheEncryptedAssertionIsDecrypted()
    {
        $xml = $this->getEncryptedResponse();
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
        $nameId = $response->getNameId();

        // Another EncryptedData, with another Assertion, before the EncryptedAssertion
        list($cipherValue, $keyCipherValue) = $this->encryptForSP(self::ASSERTION, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
        $otherEncryptedData = $this->buildEncryptedData(
            XMLSecurityKey::AES128_CBC,
            $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, $keyCipherValue),
            $cipherValue
        );
        $attack = preg_replace('#<samlp:Status>#', '<samlp:Extensions>'.$otherEncryptedData.'</samlp:Extensions><samlp:Status>', $xml, 1);
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($attack));
        $this->assertSame($nameId, $response->getNameId());
        $this->assertEquals(1, OneLogin_Saml2_Utils::query($response->getXMLDocument(), '/samlp:Response/samlp:Extensions/xenc:EncryptedData')->length);

        // An EncryptedAssertion that is not a child of the Response
        preg_match('#<saml:EncryptedAssertion>.*</saml:EncryptedAssertion>#s', $xml, $encryptedAssertion);
        $attack = preg_replace('#<samlp:Status>#', '<samlp:Extensions>'.$encryptedAssertion[0].'</samlp:Extensions><samlp:Status>', str_replace($encryptedAssertion[0], '', $xml), 1);
        $this->assertResponseRejected($attack, $this->getSettings(), OneLogin_Saml2_ValidationError::MISSING_ENCRYPTED_ELEMENT, 'Cannot locate encrypted assertion');

        // An EncryptedID that is not in the Subject of the Assertion
        list($idCipherValue, $idKeyCipherValue) = $this->encryptForSP('<saml:NameID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">object-nameid</saml:NameID>', XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
        $encryptedId = '<saml:EncryptedID>'.$this->buildEncryptedData(
            XMLSecurityKey::AES128_CBC,
            $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, $idKeyCipherValue),
            $idCipherValue
        ).'</saml:EncryptedID>';
        $assertion = str_replace('<saml:Subject>', '<ds:Signature xmlns:ds="'.OneLogin_Saml2_Constants::NS_DS.'"><ds:Object>'.$encryptedId.'</ds:Object></ds:Signature><saml:Subject>', self::ASSERTION);
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($this->buildEncryptedResponse($assertion, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P)));
        $this->assertFalse($response->encryptedNameId);
        $this->assertSame('forged-nameid', $response->getNameId());
        $this->assertEquals(1, OneLogin_Saml2_Utils::query($response->getXMLDocument(), '//ds:Object/saml:EncryptedID')->length);
    }

    /**
     * xmlseclibs 3.x also follows the RetrievalMethod / EncryptedKey children
     * (in any namespace) of the ds:KeyInfo of a Signature, that is not covered
     * by the signature. With a Response whose Assertion is signed, an
     * EncryptedKey outside the Assertion referenced from that KeyInfo
     * exhausts the memory of the PHP process. They are rejected before the
     * Signature is processed.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Utils::validateSignatureStructure
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testSignatureKeyInfoReferencesAreRejected()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_assertion_response.xml.base64'));
        $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($xml));
        $this->assertTrue($response->isValid());

        $retrievalMethod = '<ds:RetrievalMethod xmlns:ds="'.OneLogin_Saml2_Constants::NS_DS.'" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#k1"/>';
        $loopKey = $this->buildEncryptedKey(XMLSecurityKey::RSA_OAEP_MGF1P, 'AAAA', 'k1', $retrievalMethod);
        $xml = preg_replace('#<samlp:Status>#', '<samlp:Extensions>'.$loopKey.'</samlp:Extensions><samlp:Status>', $xml, 1);

        $keyInfoChildren = array(
            $retrievalMethod,
            '<r:RetrievalMethod xmlns:r="urn:other" Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#k1"/>',
            $loopKey,
        );
        foreach ($keyInfoChildren as $keyInfoChild) {
            $attack = preg_replace('#</ds:X509Data>\s*</ds:KeyInfo>#', '</ds:X509Data>'.$keyInfoChild.'</ds:KeyInfo>', $xml, 1);
            $this->assertContains($keyInfoChild.'</ds:KeyInfo>', $attack);

            $response = new OneLogin_Saml2_Response($this->getSettings(), base64_encode($attack));
            $this->assertFalse($response->isValid());
            $this->assertEquals('Unsupported KeyInfo in the Signature', $response->getError());
        }
    }

    /**
     * With strict mode and wantMessagesSigned, the Response signature (that also
     * covers the EncryptedAssertion) is verified before decrypting: modified
     * ciphertexts never reach the decryption code, which removes the padding
     * oracles of GHSA-39hg-wfcm-v4wv and GHSA-7h47-29x2-r2gc. The Response is not
     * decrypted and isValid() reports the cause, as for any other invalid message
     * (the constructor does not raise it).
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testSignedMessageIsVerifiedBeforeDecrypting()
    {
        // Response signed by the IdP, EncryptedAssertion with rsa-1_5 + aes128-cbc
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64'));
        preg_match_all('#<xenc:CipherValue>([^<]+)</xenc:CipherValue>#', $xml, $matches);
        $keyCipherValue = $matches[1][0];
        $cipherValue = $matches[1][1];

        $settings = $this->getSettings(array('wantMessagesSigned' => true), true);
        $response = new OneLogin_Saml2_Response($settings, base64_encode($xml));
        $this->assertTrue($response->encrypted);
        $this->assertNotEmpty($response->getNameId());

        $attacks = array(
            'rsa-1_5 key modified' => str_replace($keyCipherValue, base64_encode($this->randomBytes(128)), $xml),
            'cbc last byte modified' => str_replace($cipherValue, $this->flipByte($cipherValue, -1), $xml),
        );
        foreach ($attacks as $name => $attack) {
            $this->assertResponseNotDecrypted($attack, $settings, 'Reference validation failed', null, $name);

            // In strict mode a signed Response is verified before decrypting also when signed messages are not required
            $this->assertResponseNotDecrypted($attack, $this->getSettings(array(), true), 'Reference validation failed', null, $name);

            // Without strict mode the same input is decrypted (and fails with the generic error)
            $this->assertResponseRejected($attack, $this->getSettings(array('wantMessagesSigned' => true)), OneLogin_Saml2_ValidationError::DECRYPTION_FAILED, OneLogin_Saml2_Utils::DECRYPTION_FAILED_MESSAGE, $name);
        }

        $notSignedMessage = 'The Message of the Response is not signed and the SP requires it';
        $this->assertResponseNotDecrypted($this->getEncryptedResponse(), $settings, $notSignedMessage, OneLogin_Saml2_ValidationError::NO_SIGNED_MESSAGE);
        $signatureRemoved = preg_replace('#<ds:Signature\b.*?</ds:Signature>#s', '', $xml);
        $this->assertResponseNotDecrypted($signatureRemoved, $settings, $notSignedMessage, OneLogin_Saml2_ValidationError::NO_SIGNED_MESSAGE);

        // An unsigned Response is decrypted when signed messages are not required
        $response = new OneLogin_Saml2_Response($this->getSettings(array(), true), base64_encode($signatureRemoved));
        $this->assertTrue($response->encrypted);
    }

    /**
     * Without strict mode the Response signature is not verified before
     * decrypting, so isValid() must still verify it (it must not be taken as
     * already verified): a tampered signed Response with an EncryptedAssertion
     * is rejected.
     *
     * @covers OneLogin_Saml2_Response::__construct
     * @covers OneLogin_Saml2_Response::isValid
     */
    public function testSignedMessageWithEncryptedAssertionIsVerifiedWithoutStrictMode()
    {
        $xml = base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_encrypted_assertion.xml.base64'));
        $tampered = str_replace('<samlp:Response ', '<samlp:Response Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained" ', $xml);

        foreach (array(false, true) as $wantMessagesSigned) {
            $settings = $this->getSettings(array('wantMessagesSigned' => $wantMessagesSigned));

            $response = new OneLogin_Saml2_Response($settings, base64_encode($xml));
            $this->assertTrue($response->encrypted);
            $this->assertTrue($response->isValid(), (string) $response->getError());

            $response = new OneLogin_Saml2_Response($settings, base64_encode($tampered));
            $this->assertTrue($response->encrypted);
            $this->assertFalse($response->isValid());
            $this->assertEquals('Reference validation failed', $response->getError());
        }
    }

    /**
     * The Signature must cover the element it is attached to (or one of its
     * ancestors): a valid IdP signature of another element of the document,
     * moved under the Response, does not authenticate the Response. In strict
     * mode it would otherwise let a tampered EncryptedAssertion reach the
     * decryption code, as the Response signature is verified before decrypting.
     *
     * @covers OneLogin_Saml2_Utils::validateSign
     * @covers OneLogin_Saml2_Response::__construct
     */
    public function testSignatureMustCoverTheElementItIsAttachedTo()
    {
        $spCert = $this->getSettings()->getSPcert();
        $xml = str_replace(
            '<samlp:Status>',
            '<samlp:Extensions><x:Foo xmlns:x="urn:x" ID="_foo">content</x:Foo></samlp:Extensions><samlp:Status>',
            $this->buildEncryptedResponse(self::ASSERTION, XMLSecurityKey::AES128_CBC, XMLSecurityKey::RSA_OAEP_MGF1P)
        );

        // Signature of the Foo element, attached to the Foo element: valid
        $dom = new DOMDocument();
        $dom->loadXML($xml);
        $foo = $dom->getElementsByTagNameNS('urn:x', 'Foo')->item(0);
        $this->signElement($foo, $foo);
        $this->assertTrue(OneLogin_Saml2_Utils::validateSign($dom, $spCert));

        // The same Signature attached to the Response
        $dom = new DOMDocument();
        $dom->loadXML($xml);
        $foo = $dom->getElementsByTagNameNS('urn:x', 'Foo')->item(0);
        $issuer = $dom->getElementsByTagNameNS(OneLogin_Saml2_Constants::NS_SAML, 'Issuer')->item(0);
        $this->signElement($foo, $dom->documentElement, $issuer->nextSibling);
        try {
            OneLogin_Saml2_Utils::validateSign($dom, $spCert, null, 'sha1', OneLogin_Saml2_Utils::RESPONSE_SIGNATURE_XPATH);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertEquals('The Signature does not cover the element it is attached to', $e->getMessage());
        }

        $settingsInfo = $this->_settingsInfo;
        $settingsInfo['strict'] = true;
        $settingsInfo['idp']['x509cert'] = $spCert;
        foreach (array(true, false) as $wantMessagesSigned) {
            $settingsInfo['security']['wantMessagesSigned'] = $wantMessagesSigned;
            $this->assertResponseNotDecrypted($dom->saveXML(), new OneLogin_Saml2_Settings($settingsInfo), 'The Signature does not cover the element it is attached to');
        }
    }

    /**
     * Returns the settings1.php Settings with the given strict mode and security values.
     *
     * @param array $security Security values to override
     * @param bool  $strict   Strict mode
     *
     * @return OneLogin_Saml2_Settings
     */
    private function getSettings(array $security = array(), $strict = false)
    {
        $settingsInfo = $this->_settingsInfo;
        $settingsInfo['strict'] = $strict;
        $settingsInfo['security'] = array_merge($settingsInfo['security'], $security);
        return new OneLogin_Saml2_Settings($settingsInfo);
    }

    /**
     * Signs an element with the SP key (rsa-sha256, exc-c14n) and inserts the
     * Signature in another (or the same) element.
     *
     * @param DOMElement   $signedElement Element referenced by the Signature
     * @param DOMElement   $parent        Element where the Signature is inserted
     * @param DOMNode|null $beforeNode    Child of $parent before which it is inserted (appended if null)
     */
    private function signElement(DOMElement $signedElement, DOMElement $parent, $beforeNode = null)
    {
        $dsig = new XMLSecurityDSig();
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $signedElement,
            XMLSecurityDSig::SHA256,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            array('id_name' => 'ID', 'overwrite' => false)
        );
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        $key->loadKey($this->getSettings()->getSPkey());
        $dsig->sign($key);
        $dsig->add509Cert($this->getSettings()->getSPcert());
        $dsig->insertSignature($parent, $beforeNode);
    }

    /**
     * @return XMLSecurityKey The SP private key, as loaded by the toolkit to decrypt
     */
    private function getSPKey()
    {
        $seckey = new XMLSecurityKey(XMLSecurityKey::RSA_1_5, array('type' => 'private'));
        $seckey->loadKey($this->getSettings()->getSPkey());
        return $seckey;
    }

    /**
     * @return string SAML Response signed by the IdP of settings1.php (rsa-sha1, exc-c14n)
     */
    private function getSignedResponse()
    {
        return base64_decode(file_get_contents(TEST_ROOT . '/data/responses/signed_message_response.xml.base64'));
    }

    /**
     * @return string SAML Response with an EncryptedAssertion for the SP of settings1.php (rsa-1_5 + aes128-cbc)
     */
    private function getEncryptedResponse()
    {
        return base64_decode(file_get_contents(TEST_ROOT . '/data/responses/valid_encrypted_assertion.xml.base64'));
    }

    /**
     * Switches the SignatureMethod to hmac-sha1 and computes the HMAC of the
     * SignedInfo with the given (public) key material as secret.
     *
     * @param string $xml    Signed XML
     * @param string $secret HMAC secret
     *
     * @return string The forged XML
     */
    private function forgeHmacSignature($xml, $secret)
    {
        $dom = new DOMDocument();
        $dom->loadXML(str_replace(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1, $xml));
        $signedInfo = $dom->getElementsByTagNameNS(OneLogin_Saml2_Constants::NS_DS, 'SignedInfo')->item(0);
        $signatureValue = $dom->getElementsByTagNameNS(OneLogin_Saml2_Constants::NS_DS, 'SignatureValue')->item(0);
        $signatureValue->nodeValue = base64_encode(hash_hmac('sha1', $signedInfo->C14N(true, false), $secret, true));
        return $dom->saveXML();
    }

    /**
     * Encrypts a plaintext for the SP, as anyone can do with the certificate
     * published in its metadata.
     *
     * @param string $plaintext     Plaintext
     * @param string $dataAlgorithm Data encryption algorithm
     * @param string $keyAlgorithm  Key transport algorithm
     *
     * @return array CipherValue of the data and CipherValue of the EncryptedKey
     */
    private function encryptForSP($plaintext, $dataAlgorithm, $keyAlgorithm)
    {
        $symmetricKey = new XMLSecurityKey($dataAlgorithm);
        $symmetricKey->generateSessionKey();

        $keyTransport = new XMLSecurityKey($keyAlgorithm, array('type' => 'public'));
        $keyTransport->loadKey($this->getSettings()->getSPcert(), false, true);

        return array(
            base64_encode($symmetricKey->encryptData($plaintext)),
            base64_encode($keyTransport->encryptData($symmetricKey->key))
        );
    }

    /**
     * @param string      $keyAlgorithm   Key transport algorithm
     * @param string      $cipherValue    CipherValue
     * @param string|null $id             Id attribute
     * @param string|null $keyInfoContent Content of the ds:KeyInfo element
     *
     * @return string xenc:EncryptedKey element
     */
    private function buildEncryptedKey($keyAlgorithm, $cipherValue, $id = null, $keyInfoContent = null)
    {
        $idAttribute = isset($id) ? ' Id="'.$id.'"' : '';
        $keyInfo = isset($keyInfoContent) ? '<ds:KeyInfo xmlns:ds="'.OneLogin_Saml2_Constants::NS_DS.'">'.$keyInfoContent.'</ds:KeyInfo>' : '';
        return '<xenc:EncryptedKey xmlns:xenc="'.OneLogin_Saml2_Constants::NS_XENC.'"'.$idAttribute.'><xenc:EncryptionMethod Algorithm="'.$keyAlgorithm.'"/>'.$keyInfo.'<xenc:CipherData><xenc:CipherValue>'.$cipherValue.'</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>';
    }

    /**
     * @param string $dataAlgorithm  Data encryption algorithm
     * @param string $keyInfoContent Content of the ds:KeyInfo element
     * @param string $cipherValue    CipherValue
     *
     * @return string xenc:EncryptedData element
     */
    private function buildEncryptedData($dataAlgorithm, $keyInfoContent, $cipherValue)
    {
        return '<xenc:EncryptedData xmlns:xenc="'.OneLogin_Saml2_Constants::NS_XENC.'" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="'.$dataAlgorithm.'"/><ds:KeyInfo xmlns:ds="'.OneLogin_Saml2_Constants::NS_DS.'">'.$keyInfoContent.'</ds:KeyInfo><xenc:CipherData><xenc:CipherValue>'.$cipherValue.'</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>';
    }

    /**
     * @param string $encryptedAssertionContent Content of the saml:EncryptedAssertion element
     *
     * @return string SAML Response
     */
    private function buildResponse($encryptedAssertionContent)
    {
        return '<samlp:Response xmlns:samlp="'.OneLogin_Saml2_Constants::NS_SAMLP.'" xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'" ID="_forged_response" Version="2.0" IssueInstant="2014-03-29T12:01:57Z" Destination="http://stuff.com/endpoints/endpoints/acs.php"><saml:Issuer>http://idp.example.com/</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:EncryptedAssertion>'.$encryptedAssertionContent.'</saml:EncryptedAssertion></samlp:Response>';
    }

    /**
     * @param string $plaintext     Assertion
     * @param string $dataAlgorithm Data encryption algorithm
     * @param string $keyAlgorithm  Key transport algorithm
     *
     * @return string SAML Response with the Assertion encrypted for the SP
     */
    private function buildEncryptedResponse($plaintext, $dataAlgorithm, $keyAlgorithm)
    {
        list($cipherValue, $keyCipherValue) = $this->encryptForSP($plaintext, $dataAlgorithm, $keyAlgorithm);
        return $this->buildResponse(
            $this->buildEncryptedData($dataAlgorithm, $this->buildEncryptedKey($keyAlgorithm, $keyCipherValue), $cipherValue)
        );
    }

    /**
     * Builds a SAML Response whose EncryptedAssertion plaintext does not declare the saml
     * namespace (the Response declares it, as when an IdP encrypts a child node), with the
     * NameID of its Subject encrypted or not.
     *
     * @param string $keyAlgorithm         Key transport algorithm of the EncryptedID
     * @param bool   $encryptNameId        Encrypt the NameID, or leave it as a NameID
     * @param bool   $declareNamespaceInId Declare the saml namespace in the EncryptedID
     *
     * @return string SAML Response
     */
    private function buildResponseWithoutNamespaceDeclarations($keyAlgorithm, $encryptNameId = true, $declareNamespaceInId = true)
    {
        $assertion = str_replace(' xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'"', '', self::ASSERTION);
        if ($encryptNameId) {
            $nameIdXml = '<saml:NameID xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'">subject-nameid</saml:NameID>';
            list($idCipherValue, $idKeyCipherValue) = $this->encryptForSP($nameIdXml, XMLSecurityKey::AES128_CBC, $keyAlgorithm);
            $namespace = $declareNamespaceInId ? ' xmlns:saml="'.OneLogin_Saml2_Constants::NS_SAML.'"' : '';
            $encryptedId = '<saml:EncryptedID'.$namespace.'>'.$this->buildEncryptedData(
                XMLSecurityKey::AES128_CBC,
                $this->buildEncryptedKey($keyAlgorithm, $idKeyCipherValue),
                $idCipherValue
            ).'</saml:EncryptedID>';
            $assertion = preg_replace('#<saml:NameID .*</saml:NameID>#', $encryptedId, $assertion);
        }

        return $this->buildEncryptedResponse($assertion, XMLSecurityKey::AES256_CBC, XMLSecurityKey::RSA_OAEP_MGF1P);
    }

    /**
     * Returns PKCS#1 v1.5 encryption blocks (00 02 PS 00 key) of the size of
     * the SP key, as chosen by an attacker in a Bleichenbacher attack.
     *
     * @return array Blocks and whether they are PKCS#1 v1.5 conformant, indexed by name
     */
    private function getPKCS1Blocks()
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_public($this->getSettings()->getSPcert()));
        $size = $details['bits'] / 8;

        return array(
            'not conformant, 00 03 prefix' => array(
                'block' => "\x00\x03".$this->nonZeroBytes($size - 2),
                'conformant' => false,
            ),
            'not conformant, no separator' => array(
                'block' => "\x00\x02".$this->nonZeroBytes($size - 2),
                'conformant' => false,
            ),
            'not conformant, padding of 7 bytes' => array(
                'block' => "\x00\x02".$this->nonZeroBytes(7)."\x00".$this->nonZeroBytes($size - 10),
                'conformant' => false,
            ),
            'conformant, key of 5 bytes' => array(
                'block' => "\x00\x02".$this->nonZeroBytes($size - 8)."\x00".$this->nonZeroBytes(5),
                'conformant' => true,
            ),
            'conformant, key of 16 bytes' => array(
                'block' => "\x00\x02".$this->nonZeroBytes($size - 19)."\x00".$this->nonZeroBytes(16),
                'conformant' => true,
            ),
        );
    }

    /**
     * @param array $blocks Blocks returned by getPKCS1Blocks()
     *
     * @return array RSA ciphertexts for the SP key, indexed by name: the given
     *               blocks plus one bigger than the modulus, that any OpenSSL
     *               fails to decrypt
     */
    private function getRSA15Ciphertexts(array $blocks)
    {
        $ciphertexts = array();
        foreach ($blocks as $name => $block) {
            $ciphertexts[$name] = $this->rawRSAEncryptForSP($block['block']);
        }
        $ciphertexts['rsa decryption error'] = str_repeat("\xff", strlen(reset($ciphertexts)));
        return $ciphertexts;
    }

    /**
     * @param string $block Block of the size of the SP key
     *
     * @return string The block encrypted with the SP public key, without padding
     */
    private function rawRSAEncryptForSP($block)
    {
        $publicKey = openssl_pkey_get_public($this->getSettings()->getSPcert());
        openssl_public_encrypt($block, $encrypted, $publicKey, OPENSSL_NO_PADDING);
        return $encrypted;
    }

    /**
     * Validates, with strict mode and wantMessagesSigned, a LogoutRequest
     * received with the HTTP-Redirect binding from an IdP that uses the SP key
     * pair (so the tests can sign it).
     *
     * @param string $request   LogoutRequest XML
     * @param array  $security  Security values to override
     * @param string $signature 'valid', 'invalid' or 'none'
     *
     * @return array Result of isValid() and error
     */
    private function validateLogoutRequest($request, array $security, $signature = 'valid')
    {
        $settingsInfo = $this->_settingsInfo;
        $settingsInfo['strict'] = true;
        $settingsInfo['security'] = array_merge($settingsInfo['security'], array('wantMessagesSigned' => true), $security);
        $settingsInfo['idp']['x509cert'] = $this->getSettings()->getSPcert();
        $settings = new OneLogin_Saml2_Settings($settingsInfo);

        $samlRequest = base64_encode(gzdeflate($request));
        $_GET = array('SAMLRequest' => $samlRequest);
        if ($signature !== 'none') {
            $_GET['SigAlg'] = XMLSecurityKey::RSA_SHA256;
            $signedQuery = 'SAMLRequest='.urlencode($samlRequest).'&SigAlg='.urlencode($_GET['SigAlg']);
            openssl_sign($signedQuery, $signatureValue, $settings->getSPkey(), OPENSSL_ALGO_SHA256);
            if ($signature === 'invalid') {
                $signatureValue = strrev($signatureValue);
            }
            $_GET['Signature'] = base64_encode($signatureValue);
        }

        $logoutRequest = new OneLogin_Saml2_LogoutRequest($settings, $samlRequest);
        $result = array($logoutRequest->isValid(), $logoutRequest->getError());
        $_GET = array();
        return $result;
    }

    /**
     * @param string $ciphertext   RSA ciphertext of an EncryptedKey
     * @param int    $keySize      Expected key size
     * @param string $keyAlgorithm Key transport algorithm of the EncryptedKey
     *
     * @return string The key returned by OneLogin_Saml2_Utils::decryptSymmetricKey
     */
    private function decryptSymmetricKey($ciphertext, $keySize, $keyAlgorithm = XMLSecurityKey::RSA_1_5)
    {
        $dom = new DOMDocument();
        $dom->loadXML($this->buildEncryptedKey($keyAlgorithm, base64_encode($ciphertext)));
        $keyInfo = XMLSecurityKey::fromEncryptedKeyElement($dom->documentElement);
        $keyInfo->loadKey($this->getSettings()->getSPkey());
        return OneLogin_Saml2_Utils::decryptSymmetricKey($keyInfo->encryptedCtx, $keyInfo, $keySize);
    }

    /**
     * @param int $length Number of bytes
     *
     * @return string Random bytes
     */
    private function randomBytes($length)
    {
        return openssl_random_pseudo_bytes($length);
    }

    /**
     * @param int $length Number of bytes
     *
     * @return string Random bytes, none of them 0x00
     */
    private function nonZeroBytes($length)
    {
        return str_replace("\x00", "\x01", $this->randomBytes($length));
    }

    /**
     * @param string $base64   Base64 encoded data
     * @param int    $position Position of the byte to modify (negative from the end)
     *
     * @return string Base64 encoded data with one bit flipped
     */
    private function flipByte($base64, $position)
    {
        $data = base64_decode($base64);
        if ($position < 0) {
            $position += strlen($data);
        }
        $data[$position] = chr(ord($data[$position]) ^ 0x01);
        return base64_encode($data);
    }

    /**
     * @param string                  $xml      SAML Response
     * @param OneLogin_Saml2_Settings $settings Settings
     * @param int                     $code     Expected OneLogin_Saml2_ValidationError code
     * @param string                  $message  Expected OneLogin_Saml2_ValidationError message
     * @param string                  $name     Name of the attack
     */
    private function assertResponseRejected($xml, OneLogin_Saml2_Settings $settings, $code, $message, $name = '')
    {
        try {
            new OneLogin_Saml2_Response($settings, base64_encode($xml));
            $this->fail('OneLogin_Saml2_ValidationError was not raised: '.$name);
        } catch (OneLogin_Saml2_ValidationError $e) {
            $this->assertEquals($message, $e->getMessage(), $name);
            $this->assertEquals($code, $e->getCode(), $name);
        }
    }

    /**
     * The Response is built (the EncryptedAssertion is not decrypted) and isValid() reports the cause.
     *
     * @param string                  $xml      SAML Response
     * @param OneLogin_Saml2_Settings $settings Settings
     * @param string                  $message  Expected error message
     * @param int|null                $code     Expected OneLogin_Saml2_ValidationError code (null if the cause is not a OneLogin_Saml2_ValidationError)
     * @param string                  $name     Name of the attack
     */
    private function assertResponseNotDecrypted($xml, OneLogin_Saml2_Settings $settings, $message, $code = null, $name = '')
    {
        $response = new OneLogin_Saml2_Response($settings, base64_encode($xml));
        $this->assertFalse($response->encrypted, $name);
        $this->assertFalse($response->isValid(), $name);
        $this->assertEquals($message, $response->getError(), $name);
        $this->assertEquals($message, $response->getErrorException()->getMessage(), $name);
        if ($code !== null) {
            $this->assertInstanceOf('OneLogin_Saml2_ValidationError', $response->getErrorException(), $name);
            $this->assertEquals($code, $response->getErrorException()->getCode(), $name);
        }
    }

    /**
     * @param string|DOMDocument $xml     Signed SAML Response
     * @param string             $message Expected exception message
     */
    private function assertSignatureRejected($xml, $message)
    {
        try {
            OneLogin_Saml2_Utils::validateSign($xml, $this->_settingsInfo['idp']['x509cert'], null, 'sha1', OneLogin_Saml2_Utils::RESPONSE_SIGNATURE_XPATH);
            $this->fail('Exception was not raised');
        } catch (Exception $e) {
            $this->assertEquals($message, $e->getMessage());
        }
    }
}
