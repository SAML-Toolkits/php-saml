<?php

namespace OneLogin\Saml2\Tests;

use OneLogin\Saml2\Constants;
use RobRichards\XMLSecLibs\XMLSecurityDSig;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use DOMDocument;
use DOMElement;

trait SignedMessageTrait
{
    /**
     * Signs a node with the key of the SP of the test settings (used here as the key of the IdP,
     * whose certificate must be configured with the certificate of the SP) and attaches the
     * Signature to an element.
     *
     * @param DOMDocument|DOMElement $signedNode Node to sign
     * @param DOMElement             $parent     Element that will contain the Signature
     * @param string|null            $uri        URI to write in the Reference instead of the one of the signed node
     */
    protected function signNode($signedNode, DOMElement $parent, $uri = null)
    {
        $options = array('id_name' => 'ID', 'overwrite' => false);
        if ($signedNode instanceof DOMDocument) {
            $options['force_uri'] = true;
        }

        $dsig = new XMLSecurityDSig();
        $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
        $dsig->addReference(
            $signedNode,
            XMLSecurityDSig::SHA256,
            array('http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N),
            $options
        );
        if ($uri !== null) {
            $dsig->sigNode->getElementsByTagNameNS(Constants::NS_DS, 'Reference')->item(0)->setAttribute('URI', $uri);
        }

        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, array('type' => 'private'));
        $key->loadKey(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.key'));
        $dsig->sign($key);
        $dsig->add509Cert(file_get_contents(TEST_ROOT . '/data/customPath/certs/sp.crt'));
        $dsig->appendSignature($parent, true);
    }

    /**
     * @return DOMElement The Assertion of a Response built by buildResponseToSign
     */
    protected function assertionOf(DOMDocument $dom)
    {
        return $dom->getElementsByTagNameNS(Constants::NS_SAML, 'Assertion')->item(0);
    }

    /**
     * @return DOMElement The extra element (urn:x:Foo) of a Response built by buildResponseToSign
     */
    protected function fooOf(DOMDocument $dom)
    {
        return $dom->getElementsByTagNameNS('urn:x', 'Foo')->item(0);
    }

    /**
     * @param string      $assertionId ID of the Assertion
     * @param string      $nameId      NameID of the Assertion
     * @param string|null $fooId       ID of an extra element (urn:x:Foo) of the Response
     * @param string      $responseId  ID of the Response
     *
     * @return DOMDocument SAML Response without signatures
     */
    protected function buildResponseToSign($assertionId, $nameId, $fooId = null, $responseId = '_response')
    {
        $foo = $fooId !== null ? '<samlp:Extensions><x:Foo xmlns:x="urn:x" ID="' . htmlspecialchars($fooId, ENT_QUOTES) . '">content</x:Foo></samlp:Extensions>' : '';

        $dom = new DOMDocument();
        $dom->loadXML(
            '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML . '" ID="' . htmlspecialchars($responseId, ENT_QUOTES) . '" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>' . $foo
            . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
            . '<saml:Assertion ID="' . htmlspecialchars($assertionId, ENT_QUOTES) . '" Version="2.0" IssueInstant="2014-03-31T18:23:24Z">'
            . '<saml:Issuer>http://idp.example.com/</saml:Issuer>'
            . '<saml:Subject><saml:NameID>' . htmlspecialchars($nameId, ENT_QUOTES) . '</saml:NameID></saml:Subject>'
            . '</saml:Assertion></samlp:Response>'
        );

        return $dom;
    }
}
