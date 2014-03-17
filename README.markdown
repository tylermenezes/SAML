# SAML for PHP

This library will automatically load and parse SAML requests, and authenticate them in response.

This was originally made to authenticate users with Google Apps, not to follow the entire SAML spec, so it may not do
everything you need. If it's missing features, send a pull request. Note that any contributions must be licensed under
the Artistic License 2.0.

# Sample Use

This code will authenticate a user with Google Apps:

    if (array_key_exists('SAMLRequest', $_REQUEST)) {

        $request = new SAML\Request();
        $assertion = new SAML\Assertion();

        $assertion->Request = $request;
        $assertion->IssuedAt = time();
        $assertion->AuthenticatedAt = time() - 120;
        $assertion->AssertionValidAt = time() - 30;
        $assertion->AssertionExpiresAt = time() + 300;
        $assertion->SessionExpiresAt = time() + (3600*8);
        $assertion->Audience = 'google.com';

        $assertion->Issuer = 'YOURDOMAIN.COM';
        $assertion->PublicKey = file_get_contents('PRIVATE.KEY');
        $assertion->PrivateKey = file_get_contents('PUBLIC.KEY');
        $assertion->Email = 'USER@YOURDOMAIN.COM';

        $assertion->Respond();
    } else {
        header('Location: https://mail.google.com/a/YOURDOMAIN.COM');
    }


## Generating a Certificate for Google Apps

Run the following commands in the directory where you'd like your certificates saved:

    openssl genrsa -des3 -out server.key 1024
    openssl rsa -in server.key -out server.pem
    openssl req -new -key server.key -out server.csr
    openssl x509 -req -days 9999 -in server.csr -signkey server.key -out server.crt

Then go to your Google Apps control panel, Advanced settings, SSO, and upload your server.crt.

## More Google Apps Help

Sign-in page URL should be the page where you generate the SAML request.

Sign-out page URL should be a URL includes the following:

    <iframe src="https://mail.google.com/a/YOURDOMAIN.COM/?logout&amp;hl=en&amp;hlor" style="width:1px;height:1px;visibility:hidden"></iframe>
    <iframe src="https://www.google.com/a/cpanel/logout?continue=https://www.google.com/a/cpanel/YOURDOMAIN.COM" style="width:1px;height:1px;visibility:hidden"></iframe>

(These iframes won't actually load because of X-Frame-Options, but Google will still log the user out.)

Change password URL should be, obviously, a URL where the user can change their SSO password.

Domain specific issuers aren't useful unless you know you need it. (Most likely if you have a general SAML responder
endpoint which needs to authenticate users for multiple Google Apps domains.)

If you would like to force everyone, including administrators, to sign in with SAML, set the Network Mask to
`0.0.0.0/1; 128.0.0.0/1`.