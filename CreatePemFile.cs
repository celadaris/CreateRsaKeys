using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CreatePemFiles
{
    class Program
    {
        const string publicFileLocation = @"C:\Users\x\Documents\PublicKey.pem";
        const string privateFileLocation = @"C:\Users\x\Documents\PrivateKey.pem";

        static void Main(string[] args)
        {
            //rSAKeyPairGenerator generates the RSA key pair based on the random number and strength of the key required
            RsaKeyPairGenerator rSAKeyPair = new RsaKeyPairGenerator();
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.SetSeed(secureRandom.GenerateSeed(1000));
            rSAKeyPair.Init(new KeyGenerationParameters(secureRandom, 2048));
            AsymmetricCipherKeyPair keyPair = rSAKeyPair.GenerateKeyPair();

            //Extract private/public key from the pair
            RsaKeyParameters privateKey = keyPair.Private as RsaKeyParameters;
            RsaKeyParameters publicKey = keyPair.Public as RsaKeyParameters;

            //print public & private key in pem format
            CreatePem(publicKey);
            CreatePem(privateKey);

        }
        
        static void CreatePem(RsaKeyParameters key)
        {
            TextWriter textWriterPublic = new StringWriter();
            PemWriter pemWriterPublic = new PemWriter(textWriterPublic);
            string printKey;
            string fileLocation;

            pemWriterPublic.WriteObject(key);
            pemWriterPublic.Writer.Flush();
            printKey = textWriterPublic.ToString();

            if (key.IsPrivate)
            {
                fileLocation = privateFileLocation;
            }
            else
            {
                fileLocation = publicFileLocation;
            }

            File.WriteAllText(fileLocation, printKey);
        }
    }
}
