<?php


include 'vendor/autoload.php';

use Elliptic\EC;

$ecprovider = new EC("secp256k1");
$key_pair = $ecprovider->genKeyPair();

echo "public key : " . $key_pair->getPublic('hex');
echo "<br/>";
echo "private key : " . $key_pair->getPrivate('hex');

?>