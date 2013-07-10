# Using the SSO demo with a Shibboleth IdP

Marco Ferrante, University of Genoa (IT), 2013

This doc presumes that your Shibboleth 2.3.x IdP is located on the host myidp.mydomain
and the IdP configuration is left as in the distribution package as possible.

## Configure php-saml SSO demo

To access the IdP metadata, open the page https://myidp.mydomain/idp/shibboleth

Edit the demo/settings.php file to prepare your demo Service Provider (SP)
as follow. The SP is located on the host mysp.mydomain.

Set the IdP SSO service location URL:

    $settings->idpSingleSignOnUrl = 'https://myidp.mydomain/idp/profile/SAML2/Redirect/SSO';

From the IdP metadata, copy the signing certificate from the XML element:
    /EntityDescriptor/IDPSSODescriptor/KeyDescriptor//ds:X509Certificate
Then assign it to $settings->idpPublicCertificate as a base64 encoded string, adding
the PEM delimiters:

    $settings->idpPublicCertificate = <<<CERTIFICATE
    -----BEGIN CERTIFICATE-----
    MIIDEzCCAfugAwIBAgIURY6WhVVCjWYCYcWCDqlMw844ICQwDQYJKoZIhvcNAQEF
    ...
    ZeJSiC7aTo277OpGojx26GatQ/Z8Lzw=
    -----END CERTIFICATE-----
    CERTIFICATE;

Set the demo SP attribute consumer URL:

    $settings->spReturnUrl = 'http://mysp.mydomain/php-saml-master/demo/consume.php';

Leave other settings as default:

    $settings->spIssuer = 'php-saml';
    $settings->requestedNameIdFormat = OneLogin_Saml_Settings::NAMEID_EMAIL_ADDRESS;

## Configure encryption

If the demo runs on a plain HTTP server, without SSL encryption, Shibboleth
will produce encrypted assertions, as required e.g. by the "Interoperable SAML
2.0 Web Browser SSO Deployment Profile" (http://saml2int.org/profile).

To deal with encrypted assertions, you need a pair of private key and X.509
certificate. You can generate them using OpenSSL:

    openssl req -x509 -nodes -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365

and then copy key.pem and cert.pem in Settings the fields `spPrivateKey` and 
`spPublicCertificate` including the armour delimiters `----BEGIN *-----` and
`-----END *-----`
However, you can disable assertion encryption in the `relying-party.xml` file.

## Configure Shibboleth IdP

Access to the demo SP metadata by opening the page https://mysp.mydomain/php-saml-master/demo/metadata.php

If your IdP is already configured to load relying parties metadata from a local file,
just add the demo SP metadata to it. Otherwise, create an XML file in your Shibboleth
installazion such as `$IDP_HOME/metadata/demo.xml`:

    <EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:metadata sstc-saml-schema-metadata-2.0.xsd
            urn:mace:shibboleth:metadata:1.0 shibboleth-metadata-1.0.xsd http://www.w3.org/2001/04/xmlenc# xenc-schema.xsd
            http://www.w3.org/2000/09/xmldsig# xmldsig-core-schema.xsd">
	
        <!-- Copy here the demo SP metadata form https://mysp.mydomain/php-saml-master/demo/metadata.php -->
        <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                validUntil="2013-04-06T17:04:01Z" entityID="php-saml">
            <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="encryption">
                    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data>
                            <ds:X509Certificate>
    MIIBqTCCARICCQCbWvHIgIkD+DANBgkqhkiG9w0BAQQFADAZMRcwFQYDVQQDEw5w
    ...
                            </ds:X509Certificate>
                        </ds:X509Data>
                    </ds:KeyInfo>
                    <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
                </md:KeyDescriptor>
                <md:NameIDFormat>
                    urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
                </md:NameIDFormat>
                <md:AssertionConsumerService
                        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="http://mysp.mydomain/php-saml-master/demo/consume.php"
                        index="1"/>
                </md:SPSSODescriptor>
            </md:EntityDescriptor>
        </EntitiesDescriptor>

Be aware that demo SP metadata have a TTL of one week: adjust the value in the
`validUntil` attribute if you plan longer tests.

The KeyDescriptor element is produced in metadata if the options
`Settings->spPrivateKey` and `Settings->spPublicCertificate` are both set
with the private key and public certificate of the Service Provider.

Now, edit the `$IDP_HOME/conf/relying-party.xml` file; just after the `DefaultRelyingParty`
add element, add:

    <rp:RelyingParty id="php-saml"
              provider="https://myidp.mydomain/idp/shibboleth"
              defaultSigningCredentialRef="IdPCredential" >
       <rp:ProfileConfiguration xsi:type="saml:SAML2SSOProfile" />
       <!-- 
           Replace with this to disable encryption (a very bad idea...)
       <rp:ProfileConfiguration xsi:type="saml:SAML2SSOProfile"
                  encryptNameIds="never"
                  encryptAssertions="never" />
       -->
    </rp:RelyingParty>

If you have create the SP metadata file, add the reference to it in
the same `relying-party.xml`: in the `MetadataProvider[ChainingMetadataProvider]` element

    <metadata:MetadataProvider id="ShibbolethMetadata" xsi:type="metadata:ChainingMetadataProvider">
        <!-- other providers -->
		
        <metadata:MetadataProvider id="PHP-demo" xsi:type="metadata:FilesystemMetadataProvider"
                metadataFile="/opt/shibboleth-idp/metadata/demo.xml"
                maxRefreshDelay="P1D" />
					
    </metadata:MetadataProvider>
	
Then define the email address as a valid NameID; in the `$IDP_HOME/conf/attribute-resolver.xml` file,
uncomment the `AttributeDefinition` relative to email and add the encoder:

    <resolver:AttributeDefinition xsi:type="ad:Simple" id="email" sourceAttributeID="mail">
        <resolver:Dependency ref="myLDAP" />
        <resolver:AttributeEncoder xsi:type="enc:SAML1String" name="urn:mace:dir:attribute-def:mail" />
        <resolver:AttributeEncoder xsi:type="enc:SAML2String" name="urn:oid:0.9.2342.19200300.100.1.3" friendlyName="mail" />
        <!-- For php-saml -->
        <resolver:AttributeEncoder xsi:type="enc:SAML2StringNameID" nameFormat="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" />
    </resolver:AttributeDefinition>
	
Finally, let the new NameID be passed to the SP; in the `$IDP_HOME/conf/attribute-filter.xml` file,
add the following policy:

    <afp:AttributeFilterPolicy id="test-php-saml">
        <afp:PolicyRequirementRule xsi:type="basic:AttributeRequesterString" value="php-saml" />
        <afp:AttributeRule attributeID="email">
            <afp:PermitValueRule xsi:type="basic:ANY" />
        </afp:AttributeRule>
    </afp:AttributeFilterPolicy>

