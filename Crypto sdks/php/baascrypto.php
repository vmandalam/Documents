<!-- 
Author  :   Henry Keshishyan
Created :   05.22.2021
Comment :   Implements encryption/decryption using ECDH 

<?php

include 'vendor/autoload.php';

use Elliptic\EC;

class baascrypto {
    
    private $curve;
    private $ecprovider;
    private $senderprivatekey;
    private $partnerpublickey;
    private $algoconst;
    private $partyconst;
    private $algo = 'aes-256-ctr';


    function __construct($curvename, $senderprivatekey, $externalpublickey, $algoconst, $partyconst) 
    {
        $this->curve = $curvename;
        $this->ecprovider = new EC($this->curve);
        $this->senderprivatekey = $this->ecprovider->keyFromPrivate($senderprivatekey, 'hex');
        $this->externalpublickey = $this->ecprovider->keyFromPublic($externalpublickey, 'hex');
        $this->algoconst = $algoconst;
        $this->partyconst = $partyconst;
    }

    function encrypt($clear_data, $salt) 
    {   
        $short_term_key = $this->ecprovider->genKeyPair();
        $short_term_public_hex = base64_encode(hex2bin($short_term_key->getPublic('hex')));
        $short_term_private_hex = $short_term_key->getPrivate('hex');
                 
        $sharedkeyhex = $this->compute_shared_key($short_term_key, $this->externalpublickey);

        $key = hash('sha256', $sharedkeyhex . $this->algoconst . $this->partyconst . $salt); 
        
        $iv = "00000000000000000000000000000000";

        $encryptedtext = openssl_encrypt($clear_data, $this->algo, hex2bin($key), OPENSSL_RAW_DATA, hex2bin($iv));

        return json_encode(array(
            'encrypted_data_base64' => base64_encode($encryptedtext),
            'eph_pub_key_base64' => $short_term_public_hex
            ));

    }

    function decrypt($encrypted_data, $ephemeral_public_key, $salt) 
    {        
        $sharedkeyhex = $this->compute_shared_key($this->senderprivatekey, $this->ecprovider->keyFromPublic(bin2hex(base64_decode($ephemeral_public_key)), 'hex'));

        $key = hash('sha256', $sharedkeyhex . $this->algoconst . $this->partyconst . $salt); 
        
        $iv = "00000000000000000000000000000000";

        $cleartext = openssl_decrypt(base64_decode($encrypted_data, true), $this->algo, hex2bin($key), OPENSSL_RAW_DATA, hex2bin($iv));

        return $cleartext;
        
    }

    private function compute_shared_key($private_key, $public_key)
    {       
        $agreementkey = $private_key->derive($public_key->getPublic());

        return $agreementkey->toString('hex');
    }
}

?>
