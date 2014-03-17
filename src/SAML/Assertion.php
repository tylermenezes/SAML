<?php
namespace SAML;

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'require.php');

/**
 *
 *
 * @author      Tyler Menezes <tylermenezes@gmail.com>
 * @copyright   Copyright (c) Tyler Menezes.
 *
 */
class Assertion
{
    public $Request;

    public $IssuedAt;
    public $AuthenticatedAt;
    public $AssertionValidAt;
    public $AssertionExpiresAt;
    public $SessionExpiresAt;

    public $ID;
    public $AssertionID;
    public $Audience;

    public $Issuer;
    public $PublicKey;
    public $PrivateKey;

    public $Email;

    private function getSamlTimestamp($unixTimestamp)
    {
        return str_replace('+00:00', 'Z', gmdate("c",$unixTimestamp));
    }

    public function GetResponse($signed = true)
    {
        $id = isset($this->ID) ? $this->ID : $this->generateUniqueId(40);
        $assertionID = isset($this->AssertionID) ? $this->AssertionID : $this->generateUniqueId(40);
        $request = isset($this->Request) ? $this->Request : new \SAML\Request();

        $xml = new \DOMDocument('1.0', 'utf-8');
        $resp = $xml->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Response');

        $resp->setAttribute('ID', $id);
        $resp->setAttribute('InResponseTo', $request->ID);
        $resp->setAttribute('Version', '2.0');
        $resp->setAttribute('IssueInstant', $this->getSamlTimestamp($this->IssuedAt));
        $resp->setAttribute('Destination', $request->AssertionConsumerServiceURL);
        $xml->appendChild($resp);

        $issuer = $xml->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'samlp:Issuer', $this->Issuer);
        $resp->appendChild($issuer);

        $status = $xml->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Status');
        $resp->appendChild($status);

        $statusCode = $xml->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:StatusCode');
        $statusCode->setAttribute('Value',  'urn:oasis:names:tc:SAML:2.0:status:Success');
        $status->appendChild($statusCode);

        $assertion = $xml->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Assertion');
        $assertion->setAttributeNS('http://www.w3.org/2000/xmlns/',  'xmlns:saml',  'urn:oasis:names:tc:SAML:2.0:assertion');
        $assertion->setAttribute('ID', $assertionID);
        $assertion->setAttribute('IssueInstant', $this->getSamlTimestamp($this->IssuedAt));
        $assertion->setAttribute('Version', '2.0');
        $resp->appendChild($assertion);

        $assertion->appendChild($xml->createElement('saml:Issuer', $this->Issuer));

        $subject = $xml->createElement('saml:Subject');
        $assertion->appendChild($subject);

        $nameid = $xml->createElement('saml:NameID', $this->Email);
        $nameid->setAttribute('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:email');
        $nameid->setAttribute('SPNameQualifier', 'google.com');
        $subject->appendChild($nameid);

        $confirmation = $xml->createElement('saml:SubjectConfirmation');
        $confirmation->setAttribute('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');
        $subject->appendChild($confirmation);

        // Put in the params from before
        $confirmationdata = $xml->createElement('saml:SubjectConfirmationData');
        $confirmationdata->setAttribute('InResponseTo', $request->ID);
        $confirmationdata->setAttribute('NotOnOrAfter', $this->getSamlTimestamp($this->AssertionExpiresAt));
        $confirmationdata->setAttribute('Recipient', $request->AssertionConsumerServiceURL);
        $confirmation->appendChild($confirmationdata);

        $condition = $xml->createElement('saml:Conditions');
        $condition->setAttribute('NotBefore', $this->getSamlTimestamp($this->AssertionValidAt));
        $condition->setAttribute('NotOnOrAfter', $this->getSamlTimestamp($this->AssertionExpiresAt));
        $assertion->appendChild($condition);

        $audiencer = $xml->createElement('saml:AudienceRestriction');
        $condition->appendChild($audiencer);

        $audience = $xml->createElement('saml:Audience', $this->Audience);
        $audiencer->appendChild($audience);

        $authnstat = $xml->createElement('saml:AuthnStatement');
        $authnstat->setAttribute('AuthnInstant', $this->getSamlTimestamp($this->AuthenticatedAt));
        $authnstat->setAttribute('SessionIndex', '_'.$this->generateUniqueId(30));
        $authnstat->setAttribute('SessionNotOnOrAfter', $this->getSamlTimestamp($this->SessionExpiresAt));
        $assertion->appendChild($authnstat);

        $authncontext = $xml->createElement('saml:AuthnContext');
        $authnstat->appendChild($authncontext);

        $authncontext_ref = $xml->createElement('saml:AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password');
        $authncontext->appendChild($authncontext_ref);


        // Load the private key from the string
        if ($signed) {
            // Load the XML security libs needed to encrypt this
            require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'xmlseclibs.php');

            // Load the keys
            $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'private']);
            $objKey->loadKey($this->PrivateKey);
            //Sign the Assertion
            $secobj = new XMLSecurityDSig();
            $secobj->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
            $secobj->addReferenceList(  [$assertion],
                                        XMLSecurityDSig::SHA1,
                                        [
                                            'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
                                            XMLSecurityDSig::EXC_C14N
                                        ],
                                        [
                                            'id_name' => 'ID',
                                            'overwrite'=> false
                                        ]);
            $secobj->sign($objKey);
            $secobj->add509Cert($this->PublicKey);
            $secobj->insertSignature($assertion, $subject);
        }


        $res = $xml->saveXML();
        $res = str_replace('<?xml version="1.0"?>',  '',  $res);

        return $res;
    }

    public function Respond()
    {
        $redirectURL = $request->AssertionConsumerServiceURL;
        $relay_state = isset($this->RelayState) ? $this->RelayState : $_REQUEST['RelayState'];
        $response = base64_encode(stripslashes($this->GetResponse(true)));

        $form = <<<FORM
<doctype html><html><head><title>-></title></head>
<body><form method="post" action="$redirectURL">
    <input type="hidden" name="RelayState" value="$relay_state" />
    <input type="hidden" name="SAMLResponse" value="$response" />
    <input type="submit" value="->" />
</form><script type="text/javascript">document.forms[0].submit();</script>
</body></html>
FORM;
        print $form;
    }

    private function generateUniqueId($length) {
        $chars = "abcdef0123456789";
        $chars_len = strlen($chars);
        $uniqueID = "";
        for ($i = 0; $i < $length; $i++) {
            $uniqueID .= substr($chars,rand(0,15),1);
        }
        return 'a'.$uniqueID;
    }
} 