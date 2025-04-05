<?php

include 'baascrypto.php';

$ourcipher = new baascrypto(
    "secp256k1",
    "04b175d6eb0dd9151a5eeaf7217addc35a3e4840a2342f5aacf53a3b8d3e4aa2",     
    "04020b03fa8a6c7129fd6e773ec4aeb07be8430f062ba12e5a0a55e5c3c23e84c1dc88acf8657de0f2f69cb06d9a8f1c8a5fbef596f12b3707382a0e94276a07ff",  
    "0x0Did-aes256-CTR",
    "PayForward"
);

$salt = "7a95325f-da0c-42ac-ad05-74ea6c794294";
$text = "the message to encrypt";

$encrypted_package = $ourcipher->encrypt($text, $salt);

$theircipher = new baascrypto(
    "secp256k1",
    "f8b1899932a4042cf63dad2fd985d6af0526b22e9092d09d0cbb12694b7c00ed",     
    "04550b606bb1fee77e621abb3e2525867fa9dd874f36f4c45829dc5e95dcf869998a2158754395ce2e7cd0a327b49aeb0724d14b2f6be19eb97a557463564acccd", 
    "0x0Did-aes256-CTR",
    "PayForward"
);

$encrypted_data = json_decode($encrypted_package);

$clear_text = $theircipher->decrypt($encrypted_data->encrypted_data_base64, $encrypted_data->eph_pub_key_base64, $salt);

echo $clear_text;
?>
