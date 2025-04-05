"use strict";

const baas_crypto = require('./baascrypto');

let ourcipher = new baas_crypto(
    "secp256k1",
    "3e427703c8c7eddf4d885ec57d1b8e7570b5827e3efdd2a31c9a69d6caebef46",     //our private key
    "0490f640e921b39fc2017ce239c924062aa1b28c605fb89a0e4a6f5025917513d04b93b85d302793be22a23436c199252ac41764c9bbb1faf87278858549ca4b91",  //their public key
    "0x0Did-aes256-CTR",
    "PayForward"
);

let salt = "7a95325f-da0c-42ac-ad05-74ea6c794294";
let text = "the message to encrypt";

let encrypted_package = ourcipher.encrypt(text, salt);

let theircipher = new baas_crypto(
    "secp256k1",
    "e842d3f70ed0820697628b5c232a2c8836486ef9342ea824a36d0f3e801bacf5",     //their private key
    "04fd6eaf9c91a2e4738e9d26b8daf6d17d5e63b3eca4a3890acc3d0b294c22f0ff7185514ce3ec4bc621bde3fbe4dcb61e19fc68eead8f733729f03bc2c5419846",  //our public key
    "0x0Did-aes256-CTR",
    "PayForward"
);

let clear_text = theircipher.decrypt(encrypted_package.encrypted_data_base64, encrypted_package.eph_pub_key_base64, salt);

console.log(clear_text);

