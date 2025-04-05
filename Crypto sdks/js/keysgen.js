"use strict"

const nativecrypto = require('crypto');

const keys = nativecrypto.createECDH("secp256k1");

for(let c = 0; c < 2; c++)
{
    keys.generateKeys();
    console.log(keys.getPrivateKey('hex'));
    console.log(keys.getPublicKey('hex'));
}

