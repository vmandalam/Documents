using System;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace baas
{

    public class baascrypto
    {

        private string _curvename = String.Empty;
        private string _senderprivatekey = String.Empty;
        private string _externalpublickey = String.Empty;
        private string _algoconst = String.Empty;
        private string _partyconst = String.Empty;
        private const string _algo = "aes-256-ctr"; 


        public baascrypto(string curvename, string senderprivatekey, string externalpublickey, string algoconst, string partyconst)
        {
            this._curvename = curvename;
            this._senderprivatekey = senderprivatekey;
            this._externalpublickey = externalpublickey;
            this._algoconst = algoconst;
            this._partyconst = partyconst;
        }


        public object encrypt(string clear_data, string salt)
        {

            AsymmetricCipherKeyPair short_term_key = GenerateKeyPair();

            // ECDiffieHellmanCng short_term_key = new ECDiffieHellmanCng(256); 

            // // short_term_key.generateKeys();
            // short_term_key.GenerateKey(ECCurve.NamedCurves.nistP256);

            // // let shared_key = this.compute_shared_key(short_term_key, this._externalpublickey);
            // string shared_key = this.compute_shared_key(short_term_key, this._externalpublickey);
           
            // // const key_mash = shared_key + this._algoconst + this._partyconst + salt;
            // string key_mash = shared_key + this._algoconst + this._partyconst + salt;

            // // const iv = Buffer.from('00000000000000000000000000000000', 'hex');
            // byte[] iv = crypto.Hex2ByteArray("00000000000000000000000000000000");

            // // const key = nativecrypto.createHash("sha256").update(key_mash, "utf8").digest();
            // byte[] key;
            // using (SHA256 sha256provider = SHA256.Create())
            // {
            //     key = sha256provider.ComputeHash(Encoding.UTF8.GetBytes(key_mash));
            // }

            // // var cipher = nativecrypto.createCipheriv(this._algo, key, iv);
            // SymmetricAlgorithm aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };
            // ICryptoTransform encryptor = aes.CreateEncryptor(key, iv);
            // string base64data;
            // using (MemoryStream ms = new MemoryStream())
            // {
            //     // var encryptedPayload = cipher.update(clear_data, 'utf8', 'base64');
            //     // encryptedPayload += cipher.final('base64');
            //     using(CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))   
            //     {  
            //         // Create StreamWriter and write data to a stream    
            //         using(StreamWriter sw = new StreamWriter(cs))
            //         {
            //             sw.Write(clear_data);  
            //             base64data = Convert.ToBase64String(ms.ToArray());
            //         }  
            //     }  

            // }

            // // let ephemeral_key = short_term_key.getPublicKey('base64');
            // //short_term_key.PublicKey;

            // // return { "encrypted_data_base64" : encryptedPayload, "eph_pub_key_base64" : ephemeral_key };
            // dynamic obj = new { encrypted_data_base64 = base64data };
           
            
            // return obj;
            return null;

        }

        private string compute_shared_key(string private_key, string public_key)
        {
            // ECDiffieHellmanPublicKey publickey = ECDiffieHellmanCngPublicKey.FromByteArray(crypto.Hex2ByteArray(public_key), CngKeyBlobFormat.GenericPublicBlob); 

            // byte[] keyAgreement = private_key.DeriveKeyMaterial(publickey);

            // return crypto.ByteArray2Hex(keyAgreement);
            return null;
        }


        private static byte[] Hex2ByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private static string ByteArray2Hex(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            var curve = ECNamedCurveTable.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var secureRandom = new SecureRandom();
            var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            var generator = new ECKeyPairGenerator("ECDH");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            Console.WriteLine($"Private key: {ByteArray2Hex(privateKey.D.ToByteArrayUnsigned())}");
            Console.WriteLine($"Public key: {ByteArray2Hex(publicKey.Q.GetEncoded())}");

            return keyPair;
        }    


        private static Byte[] getSharedSecret( Byte[] PrivateKeyIn, Byte[] PublicKeyIn )
        {
            ECDHCBasicAgreement         agreement             = new ECDHCBasicAgreement();
            X9ECParameters              curve                 = null;
            ECDomainParameters          ecParam               = null;
            ECPrivateKeyParameters      privKey               = null;
            ECPublicKeyParameters       pubKey                = null;
            ECPoint                     point                 = null;

            curve     = NistNamedCurves.GetByName( "P-256" );
            ecParam   = new ECDomainParameters( curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed() );
            privKey   = new ECPrivateKeyParameters( new BigInteger( PrivateKeyIn ), ecParam );
            point     = ecParam.Curve.DecodePoint( PublicKeyIn );
            pubKey    = new ECPublicKeyParameters( point, ecParam );

            agreement.Init( privKey );

            BigInteger secret = agreement.CalculateAgreement( pubKey );

            return secret.ToByteArrayUnsigned();
        }

    
    }
    
    
}