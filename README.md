Installing: Development Environment
===================================

To install locally:

* clone this repository
* put (or symbolic-link) this repo in a place where it is accessible at: http://localhost/php-saml/

```sh
    # for example on Mac OSX: 
    cd ~/src
    git clone git://github.com/junyoed/php-saml.git

    # make sure Web Sharing is on, or that PHP is serving this directory for some reason
    cd /Library/WebServer/Documents
    ln -s ~/src/php-saml/ php-saml
```

 * in a web browser, go to http://localhost/php-saml/index.php
 * choose "auth google"
 * log in as the user you were given by Junyo

You should be redirected to a page that has a message like "You are: <GUID>".  This GUID is the Junyo ID you got from the provisioning API and represents the logged in user.

Setting up for Production
=========================

Several properties found in demo/settings.php need to be changed before you go to production.

1. $settings->spReturnUrl
This is the URL that the IdP will send users that successfully log in back to.  This page will have a SAML token posted that contains the ID of the user

2. $settings->spIssuer = 'php-saml-demo';
This should identity your application specifically. A URI, often of the format: "http://your.url.com/saml2", is an example of an appropriate value.  If you're unsure of this, contact Junyo.  

One note: there is a mapping from this value to acceptable return URLs, so this must be specific to your application.

General
=======

The files in demo are sample code to help
demonstrate how this library should work. In order to use them, you can
unpack this library in your website directory.

You will need to modify the settings.php file to set the proper URLs and
x509 certificate.

There is more information in this post: 
http://support.onelogin.com/entries/268420-saml-toolkit-for-php
