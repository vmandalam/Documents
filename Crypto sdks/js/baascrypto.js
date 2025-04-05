/*
Author  :   Henry Keshishyan
Created :   05.22.2021
Comment :   Implements encryption/decryption with ECDH key exchange and 
*/

"use strict"

const nativecrypto = require('crypto');

module.exports = class baascrypto {
    
    constructor(curvename, senderprivatekey, externalpublickey, algoconst, partyconst) 
    {
        this._curvename = curvename;
        this._senderprivatekey = senderprivatekey;
        this._externalpublickey = externalpublickey;
        this._algoconst = algoconst;
        this._partyconst = partyconst;
        this._algo = 'aes-256-ctr';            
    }

    
    encrypt = (clear_data, salt) => {

        const short_term_key = nativecrypto.createECDH(this._curvename);

        short_term_key.generateKeys();

        let shared_key = this.compute_shared_key(short_term_key, this._externalpublickey);

        const key_mash = shared_key + this._algoconst + this._partyconst + salt;

        const iv = Buffer.from('00000000000000000000000000000000', 'hex');

        const key = nativecrypto.createHash("sha256").update(key_mash, "utf8").digest();

        var cipher = nativecrypto.createCipheriv(this._algo, key, iv);

        var encryptedPayload = cipher.update(clear_data, 'utf8', 'base64');
        encryptedPayload += cipher.final('base64');

        let ephemeral_key = short_term_key.getPublicKey('base64');

        return { "encrypted_data_base64" : encryptedPayload, "eph_pub_key_base64" : ephemeral_key };
    };

    decrypt = (encrypted_data_base64, eph_pub_key_base64, salt) => {

        const private_key = nativecrypto.createECDH(this._curvename);

        private_key.setPrivateKey(this._senderprivatekey, 'hex');
        
        let ephemeral_public_key_hex = Buffer.from(eph_pub_key_base64, 'base64').toString('hex');

        let shared_key = this.compute_shared_key(private_key, ephemeral_public_key_hex);

        const key_mash = shared_key + this._algoconst + this._partyconst + salt;

        const iv = Buffer.from('00000000000000000000000000000000', 'hex');

        const key = nativecrypto.createHash("sha256").update(key_mash, "utf8").digest();

        var decipher = nativecrypto.createDecipheriv(this._algo, key, iv);

        var decryptedPayload = decipher.update(encrypted_data_base64, 'base64', 'utf8');

        return decryptedPayload;
    };


    compute_shared_key = (private_key, public_key_hex) => {

        const keyAgreement = private_key.computeSecret(Buffer.from(public_key_hex, 'hex'), null, 'hex');

        return keyAgreement;
    }


    
};