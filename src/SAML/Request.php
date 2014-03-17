<?php
namespace SAML;

require_once(dirname(__FILE__) . DIRECTORY_SEPARATOR . 'require.php');

/**
 * Represents a SAML request.
 *
 * @author      Tyler Menezes <tylermenezes@gmail.com>
 * @copyright   Copyright (c) Tyler Menezes.
 *
 */
class Request
{
    private $authnrequest;

    /**
     * @param $incoming_data string The incoming data, optionally gzipped.
     */
    public function __construct($incoming_data = null)
    {
        if (!isset($incoming_data)) {
            $incoming_data = $_REQUEST['SAMLRequest'];
        }

        if(!$xml_string = gzinflate(base64_decode($incoming_data))){
            $xml_string = $incoming_data;
        }

        $xml = new \DOMDocument();
        $xml->loadXML($xml_string);
        if($xml->hasChildNodes() && ($node = $xml->childNodes->item(0))){
            $authnrequest = array();
            foreach($node->attributes as $attr){
                $authnrequest[$attr->name] = $attr->value;
            }
            if($node->hasChildNodes()){
                foreach($node->childNodes as $childnode){
                    if($childnode->hasAttributes()){
                        $authnrequest[$childnode->nodeName]=array();
                        foreach($childnode->attributes as $attr){
                            $authnrequest[$childnode->nodeName][$attr->name] = $attr->value;
                        }
                    }else{
                        $authnrequest[$childnode->nodeName]=$childnode->nodeValue;
                    }
                }
            }
        }

        $this->authnrequest = $authnrequest;
    }

    public function __get($key) {
        return $this->authnrequest[$key];
    }
} 