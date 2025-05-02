using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;
using Ceras;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Data.HashFunction.Blake3;
using EasyCompressor;
using K4os.Compression.LZ4;
using SecureStringPlus;
using Walker.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System.Data.HashFunction;
using static Org.BouncyCastle.Math.EC.ECCurve;
using static Pariah_Cybersecurity.EasyPQC;
using Org.BouncyCastle.Crypto;
using NBitcoin;
using Org.BouncyCastle.Utilities;
using System.Security.Cryptography.X509Certificates;
using static Org.BouncyCastle.Asn1.Cmp.Challenge;
using static NBitcoin.WalletPolicies.MiniscriptNode.ParameterRequirement;
using static Walker.Crypto.SimpleAESEncryption;




namespace Pariah_Cybersecurity
{

    //TODO; Parameterize and add error checks to everything
    //Replace file readbytes with something faster (MMap?)
    //Turn a few of these into structs (Heap safety, use classes for big files only)
    //Convert a few strings to SecureString
    //CLEAN UP MESS
    //Change all SecureString.ConvertToString(true) to ConvertToString
    //Add await to where it needs to be added

    public class EasyPQC
    {


        public class Signatures //Used for fingerprint, Dilithium
        {

            public static async Task<(Dictionary<string, byte[]>, Dictionary<string, byte[]>)> CreateKeys()
            {
                // Initialize the random generator
                var randomgen = new SecureRandom();

                // Set up the key generation parameters for Dilithium5
                var param = new DilithiumKeyGenerationParameters(randomgen, DilithiumParameters.Dilithium5);

                // Create a key pair generator and initialize it with the parameters
                var keyPairGenerator = new DilithiumKeyPairGenerator();
                keyPairGenerator.Init(param);

                // Generate the key pair
                var keyPair = keyPairGenerator.GenerateKeyPair();

                // Extract the public and private key parameters
                var publicParameter = (DilithiumPublicKeyParameters)keyPair.Public;
                var privateParameter = (DilithiumPrivateKeyParameters)keyPair.Private;

                // Serialize the keys into byte arrays
                var pubkeyBytes = Encode(publicParameter);
                var privkeyBytes = Encode(privateParameter);

                // Return the keys as a ByteReturnPair
                return (pubkeyBytes, privkeyBytes);
            }

            public static async Task<byte[]> CreateSignature(Dictionary<string, byte[]> privatekeyBytes, string input)
            {
                var gensign = new DilithiumSigner();

                var privateKey = DecodePrivate(privatekeyBytes);

                gensign.Init(true, privateKey);

                var inputBytes = Encoding.UTF8.GetBytes(input);
                var signature = gensign.GenerateSignature(inputBytes);

                return signature;
            } 


            public async static Task<bool> VerifySignature(Dictionary<string, byte[]> publickeyBytes, byte[] signature, string input)
            {
                var gensign = new DilithiumSigner();

                var publicKey = DecodePublic(publickeyBytes);


                Console.Write(publicKey);

                gensign.Init(false, publicKey);

                var inputBytes = Encoding.UTF8.GetBytes(input);
                return gensign.VerifySignature(inputBytes, signature);
            }


            public async static Task<bool> VerifySignature(Dictionary<string, byte[]> publickeyBytes, byte[] signature, byte[] inputBytes)
            {
                var gensign = new DilithiumSigner();

                var publicKey = DecodePublic(publickeyBytes);

                gensign.Init(false, publicKey);

                return gensign.VerifySignature(inputBytes, signature);
            }














            internal static Dictionary<string, byte[]> Encode(DilithiumPublicKeyParameters key)
            {

                byte[] encoded = key.GetEncoded();
                byte[] rho = Arrays.CopyOfRange(encoded, 0, 32);
                byte[] t1 = Arrays.CopyOfRange(encoded, 32, encoded.Length);

                var encodedval = new Dictionary<string, byte[]>();

                encodedval.Add("rho", rho);
                encodedval.Add("t1", t1);

                return encodedval;

            }

            internal static Dictionary<string, byte[]> Encode(DilithiumPrivateKeyParameters key)
            {

                var rho = key.Rho;
                var k = key.K;
                var tr = key.Tr;
                var s1 = key.S1;
                var s2 = key.S2;
                var t0 = key.T0;
                var t1 = key.T1;


                var encodedval = new Dictionary<string, byte[]>
                {
                    ["rho"] = key.Rho,
                    ["k"] = key.K,
                    ["tr"] = key.Tr,
                    ["s1"] = key.S1,
                    ["s2"] = key.S2,
                    ["t0"] = key.T0,
                    ["t1"] = Arrays.Clone(key.T1)
                };

                return encodedval;

            }


            internal static DilithiumPublicKeyParameters DecodePublic(Dictionary<string, byte[]> key)
            {
                byte[] rho = key["rho"];
                byte[] t1 = key["t1"];

                var decodedval = new DilithiumPublicKeyParameters(DilithiumParameters.Dilithium5, rho, t1);

                return decodedval;
            }

            internal static DilithiumPrivateKeyParameters DecodePrivate(Dictionary<string, byte[]> key)
            {

                var rho = key["rho"];
                var k = key["k"];
                var tr = key["tr"];
                var s1 = key["s1"];
                var s2 = key["s2"];
                var t0 = key["t0"];
                var t1 = key["t1"];

                var decodedval = new DilithiumPrivateKeyParameters(DilithiumParameters.Dilithium5, rho, k, tr, s1, s2, t0, t1);

                return decodedval;
            }





        }

        public class Keys //Used for secrets, onetime passes, signing, kyber
        {

            public struct KeyAndEncryptedText
            {
                public byte[] key { get; private set; }
                public byte[] text { get; private set; }

                public KeyAndEncryptedText(byte[] key, byte[] text)
                {
                    this.key = key;
                    this.text = text;
                }
            }

            public static (Dictionary<string, byte[]>, Dictionary<string, byte[]>) Initiate()
            {
                var randomgen = new SecureRandom();
                var keyparams = new KyberKeyGenerationParameters(randomgen, KyberParameters.kyber1024);



                var KyberPairGen = new KyberKeyPairGenerator();
                KyberPairGen.Init(keyparams);
                var keys = KyberPairGen.GenerateKeyPair();

                var publickey = Encode((KyberPublicKeyParameters)keys.Public);
                var privatekey = Encode((KyberPrivateKeyParameters)keys.Private);

                return (publickey, privatekey);



            }

            public static KeyAndEncryptedText CreateSecret(Dictionary<string, byte[]> givenkey)
            {
                var randomgen = new SecureRandom();
                var keygen = new KyberKemGenerator(randomgen);

                var deserializedpub = DecodePublic(givenkey);

                var encapsulatedSecret = keygen.GenerateEncapsulated(deserializedpub);
                var newsecret = encapsulatedSecret.GetSecret();

                var cipher = encapsulatedSecret.GetEncapsulation();

                var returnval = new KeyAndEncryptedText(newsecret, cipher);

                return returnval; //Key is saved by user B, text is sent to user A
            }

            public static byte[] CreateSecretTwo(Dictionary<string, byte[]> privkey, byte[] cipher)
            {
                var deserializedpriv = DecodePrivate(privkey);
                var extractor = new KyberKemExtractor(deserializedpriv);
                return extractor.ExtractSecret(cipher);
            }



            //This took all 5 braincells to figure out, screw this >:'(



            internal static Dictionary<string, byte[]> Encode(KyberPrivateKeyParameters key)
            {
                byte[] encoded = key.GetEncoded();
                int symBytes = key.Parameters.SessionKeySize;
              
                int totalLen = encoded.Length;
                int knownTail = symBytes * 3;

                byte[] sAndT = Arrays.CopyOfRange(encoded, 0, totalLen - knownTail);
                byte[] rho = Arrays.CopyOfRange(encoded, totalLen - 3 * symBytes, totalLen - 2 * symBytes);
                byte[] hpk = Arrays.CopyOfRange(encoded, totalLen - 2 * symBytes, totalLen - symBytes);
                byte[] nonce = Arrays.CopyOfRange(encoded, totalLen - symBytes, totalLen);

                int half = sAndT.Length / 2;
                byte[] s = Arrays.CopyOfRange(sAndT, 0, half);
                byte[] t = Arrays.CopyOfRange(sAndT, half, sAndT.Length);

                return new Dictionary<string, byte[]>
                {
                    ["s"] = s,
                    ["t"] = t,
                    ["rho"] = rho,
                    ["hpk"] = hpk,
                    ["nonce"] = nonce
                };
            }



            internal static Dictionary<string, byte[]> Encode(KyberPublicKeyParameters key)
            {
                byte[] encoded = key.GetEncoded();
                int symBytes = key.Parameters.SessionKeySize;

                byte[] t = Arrays.CopyOfRange(encoded, 0, encoded.Length - symBytes);
                byte[] rho = Arrays.CopyOfRange(encoded, encoded.Length - symBytes, encoded.Length);

                return new Dictionary<string, byte[]>
                {
                    ["t"] = t,
                    ["rho"] = rho
                };
            }


            internal static KyberPublicKeyParameters DecodePublic(Dictionary<string, byte[]> key)
            {
                var t = key["t"];
                var rho = key["rho"];

                return new KyberPublicKeyParameters(KyberParameters.kyber1024, t, rho); // Use the correct KyberParameters variant
            }

            internal static KyberPrivateKeyParameters DecodePrivate(Dictionary<string, byte[]> key)
            {
                var s = key["s"];
                var t = key["t"];
                var rho = key["rho"];
                var hpk = key["hpk"];
                var nonce = key["nonce"];

                return new KyberPrivateKeyParameters(KyberParameters.kyber1024, s, hpk, nonce, t, rho); // Again, use the correct parameter set
            }


        }

        public class FileOperations //Compresses data using LZ4 and Hashes using Blake3 (signing), great for files, messages, etc.
        {

            //EVERYTHING IN FILE OPERATIONS NEEDS TO BE FIXED

            public struct PackedFile
            {
                public string FilePath { get; private set; }

                public string Signature { get; private set; }


                public PackedFile(string filePath, string signature)
                {
                    this.FilePath = filePath;
                    this.Signature = signature;
                }

                public override string ToString()
                {
                    return $"{FilePath}|{Signature}";
                }

                public static PackedFile FromString(string packedFileString)
                {
                    var parts = packedFileString.Split('|');
                    if (parts.Length != 2)
                    {
                        throw new ArgumentException("Invalid packed file string format");
                    }
                    return new PackedFile(parts[0], parts[1]);
                }
            }




            public enum CompressionLevel { Fast, Balanced, Max }

            public delegate void CompressionProgress(long current, long fileSize, int percentage);

            //Use this if you like this kind of suffering
            public static async Task<string> CompressFileAsync(string fileInput, string fileOutput, CompressionProgress compressionProgress, CompressionLevel compressionType)
            {
                try
                {
                    var fileInfo = new FileInfo(fileInput);
                    long fileSize = fileInfo.Length;

                    LZ4Level comptype = compressionType switch
                    {
                        CompressionLevel.Fast => LZ4Level.L00_FAST,
                        CompressionLevel.Balanced => LZ4Level.L09_HC,
                        CompressionLevel.Max => LZ4Level.L12_MAX,
                        _ => LZ4Level.L00_FAST
                    };

                    var compressor = new LZ4Compressor(comptype);

                    using var sourceStream = File.Open(fileInput, FileMode.Open, FileAccess.Read);
                    using var fileBytestream = new MemoryStream();
                    await sourceStream.CopyToAsync(fileBytestream);
                    fileBytestream.Position = 0;

                    using var compDatastream = new MemoryStream();
                    await compressor.CompressAsync(fileBytestream, compDatastream);

                    await EasyPQC.WriteAllBytesAsync(fileOutput, compDatastream.ToArray(), null);

                    return fileOutput;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Compression failed: {ex.Message}");
                    return string.Empty;
                }
            }

            public static async Task<string> DecompressFileAsync(string fileInput, string fileOutput, CompressionProgress compressionProgress, CompressionLevel compressionType)
            {
                try
                {
                    var fileInfo = new FileInfo(fileInput);
                    long fileSize = fileInfo.Length;

                    LZ4Level comptype = compressionType switch
                    {
                        CompressionLevel.Fast => LZ4Level.L00_FAST,
                        CompressionLevel.Balanced => LZ4Level.L09_HC,
                        CompressionLevel.Max => LZ4Level.L12_MAX,
                        _ => LZ4Level.L00_FAST
                    };

                    var compressor = new LZ4Compressor(comptype);

                    using var sourceStream = File.Open(fileInput, FileMode.Open, FileAccess.Read);
                    using var fileBytestream = new MemoryStream();
                    await sourceStream.CopyToAsync(fileBytestream);
                    fileBytestream.Position = 0;

                    using var compDatastream = new MemoryStream();
                    await compressor.DecompressAsync(fileBytestream, compDatastream);

                    await EasyPQC.WriteAllBytesAsync(fileOutput, compDatastream.ToArray(), null);

                    return fileOutput;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Decompression failed: {ex.Message}");
                    return string.Empty;
                }
            }

            public static async Task<byte[]> HashFile(Stream fileData)
            {
                var hashFunction = (IHashFunctionAsync)Blake3Factory.Instance.Create();
                var bytes = await hashFunction.ComputeHashAsync(fileData);
                return bytes.Hash;
            }

            public static async Task<bool> VerifyHash(Stream fileData, byte[] signature)
            {
                var fileBytes = await HashFile(fileData);
                return fileBytes.SequenceEqual(signature);
            }


            //Use this if you want an easy life

            //Compresses the file and creates a signed filehash, make sure you use .ConvertToString(true) to make this sendable
            public static async Task<PackedFile> PackFiles(string fileInput, string fileOutput, byte[] privateKey, SecureString sessionkey,
                CompressionProgress compressionProgress, CompressionLevel compressionType, bool encryptFile)
            {
                string filename = Pariah_Cybersecurity.PasswordGenerator.GeneratePassword(24, true, false, false, false);
                LZ4Level comptype = compressionType switch
                {
                    CompressionLevel.Fast => LZ4Level.L00_FAST,
                    CompressionLevel.Balanced => LZ4Level.L09_HC,
                    CompressionLevel.Max => LZ4Level.L12_MAX,
                    _ => LZ4Level.L00_FAST
                };

                var compressor = new LZ4Compressor(comptype);
                byte[] fileBytes = await EasyPQC.ReadAllBytesAsync(fileInput);

                using var inputStream = new MemoryStream(fileBytes);
                using var compressedStream = new MemoryStream();
                await compressor.CompressAsync(inputStream, compressedStream);
                byte[] compressedData = compressedStream.ToArray();

                string packedFilePath = $"{fileOutput}{filename}.pack";
                await EasyPQC.WriteAllBytesAsync(packedFilePath, compressedData, null);

                if (encryptFile)
                {
                    string encryptedPath = $"{fileOutput}{filename}.encpack";
                    await Walker.Crypto.AESFileEncryptor.EncryptFileAsync(packedFilePath, encryptedPath, sessionkey);
                    File.Delete(packedFilePath);
                    packedFilePath = encryptedPath;
                }

                var finalpriv = (DilithiumPrivateKeyParameters)PrivateKeyFactory.CreateKey(privateKey);
                var privateKeyBytes = Signatures.Encode(finalpriv);

                byte[] signatureHash = await HashFile(new MemoryStream(compressedData));
                byte[] rawSignature = await Signatures.CreateSignature(privateKeyBytes, Convert.ToBase64String(signatureHash));
                string encryptedSign = SimpleAESEncryption.Encrypt(Convert.ToBase64String(rawSignature), sessionkey).ToString();

                return new PackedFile(packedFilePath, encryptedSign);
            }


            public static async Task<bool> UnpackFile(PackedFile inputFile, string outputPath, byte[] publicKey, CompressionProgress compressionProgress, CompressionLevel compressionType, SecureString sessionkey)
            {
                bool isEncrypted = Path.GetExtension(inputFile.FilePath) == ".encpack";
                string tempFilePath = inputFile.FilePath;

                if (isEncrypted)
                {
                    tempFilePath = Path.Combine(Path.GetTempPath(), Path.GetFileNameWithoutExtension(inputFile.FilePath) + ".decrypted");
                    await Walker.Crypto.AESFileEncryptor.DecryptFileAsync(inputFile.FilePath, tempFilePath, sessionkey);
                }

                var decryptedSign = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(inputFile.Signature), sessionkey);
                byte[] expectedSignature = Convert.FromBase64String(decryptedSign.ConvertToString());

                byte[] compressedBytes = await EasyPQC.ReadAllBytesAsync(tempFilePath);
                byte[] actualHash = await HashFile(new MemoryStream(compressedBytes));
                string base64Hash = Convert.ToBase64String(actualHash);

                var finalpub = (DilithiumPrivateKeyParameters)PrivateKeyFactory.CreateKey(publicKey);
                var publicKeyBytes = Signatures.Encode(finalpub);

                if (!Signatures.VerifySignature(publicKeyBytes, expectedSignature, base64Hash).Result)
                {
                    if (isEncrypted) File.Delete(tempFilePath);
                    return false; // Signature validation failed
                }

                LZ4Level comptype = compressionType switch
                {
                    CompressionLevel.Fast => LZ4Level.L00_FAST,
                    CompressionLevel.Balanced => LZ4Level.L09_HC,
                    CompressionLevel.Max => LZ4Level.L12_MAX,
                    _ => LZ4Level.L00_FAST
                };

                var compressor = new LZ4Compressor(comptype);
                using var compressedStream = new MemoryStream(compressedBytes);
                using var decompressedStream = new MemoryStream();
                await compressor.DecompressAsync(compressedStream, decompressedStream);

                string finalOutputPath = Path.Combine(outputPath, Path.GetFileNameWithoutExtension(tempFilePath));
                await EasyPQC.WriteAllBytesAsync(finalOutputPath, decompressedStream.ToArray(), null);

                if (isEncrypted) File.Delete(tempFilePath);
                return true;
            }


        }

        public class Rotation //Handling rotating a key, AKA creating a new session key, THIS should be used as session keys
        {
            //Imagine an event here says "Time to rotate!", we will make verification logic later in Pariah Networking

            //Honestly? I completely forgot how I was gonna do this LOL the below is a general draft, ignore it for now



            public async Task <(string, string)> CreateInitialKey(string key)
            {
                // UTF-8 directly, no Base64 for salt
                var saltBytes = Encoding.UTF8.GetBytes(
                    Pariah_Cybersecurity.PasswordGenerator.GeneratePassword(32, true, true, true, false)
                );


                var keyBytes = UTF8Encoding.UTF8.GetBytes(key); // key is still Base64-encoded
                var shakeDigest = new ShakeDigest(256);

                for (int i = 0; i < 1000; i++)
                {
                    shakeDigest.BlockUpdate(keyBytes, 0, keyBytes.Length);
                    shakeDigest.BlockUpdate(saltBytes, 0, saltBytes.Length);
                    keyBytes = new byte[shakeDigest.GetDigestSize()];
                    shakeDigest.DoFinal(keyBytes, 0);
                    shakeDigest.Reset();
                }

                return (Convert.ToBase64String(saltBytes), Convert.ToBase64String(keyBytes)); // still returns Base64 output
            }


            public async Task<string> RotateKey(SecureString key, int rotations, string salt)
            {

                var utf8Key = key.ConvertToString();

                var keyBytes = UTF8Encoding.UTF8.GetBytes(utf8Key);
                var saltBytes = UTF8Encoding.UTF8.GetBytes(salt);
                var shakeDigest = new ShakeDigest(256);

                for (int i = 0; i < rotations; i++)
                {
                    shakeDigest.BlockUpdate(keyBytes, 0, keyBytes.Length);
                    shakeDigest.BlockUpdate(saltBytes, 0, saltBytes.Length);
                    keyBytes = new byte[shakeDigest.GetDigestSize()];
                    shakeDigest.DoFinal(keyBytes, 0);
                    shakeDigest.Reset(); // Optional again  
                }

                return Convert.ToBase64String(keyBytes);
            }

            public static string ToBase64(string input)
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(input);
                return Convert.ToBase64String(bytes);
            }



        }


        public static async Task WriteAllBytesAsync(string path, byte[] bytes, Action<int> progressCallback = null)
        {
            using (var sourceStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true))
            {
                long totalBytes = bytes.Length;
                long bytesWritten = 0;
                int bufferSize = 4096;
                for (int i = 0; i < bytes.Length; i += bufferSize)
                {
                    int bytesToWrite = Math.Min(bufferSize, bytes.Length - i);
                    await sourceStream.WriteAsync(bytes, i, bytesToWrite);
                    bytesWritten += bytesToWrite;
                    progressCallback?.Invoke((int)((bytesWritten * 100) / totalBytes));
                }
                await sourceStream.FlushAsync();
            }
        }

        public static async Task WriteAllBytesAsync(string path, byte[] bytes, Action<int> progressCallback = null, CancellationToken cancellationToken = default)
        {
            using (var sourceStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 4096, useAsync: true))
            {
                long totalBytes = bytes.Length;
                long bytesWritten = 0;
                int bufferSize = 4096;
                for (int i = 0; i < bytes.Length; i += bufferSize)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int bytesToWrite = Math.Min(bufferSize, bytes.Length - i);
                    await sourceStream.WriteAsync(bytes, i, bytesToWrite, cancellationToken);
                    bytesWritten += bytesToWrite;
                    progressCallback?.Invoke((int)((bytesWritten * 100) / totalBytes));
                }
                await sourceStream.FlushAsync(cancellationToken);
            }
        }

        public static async Task<byte[]> ReadAllBytesAsync(string path)
        {
            using (var sourceStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 4096, useAsync: true))
            {
                var buffer = new byte[sourceStream.Length];
                int totalRead = 0;
                while (totalRead < buffer.Length)
                {
                    int bytesRead = await sourceStream.ReadAsync(buffer, totalRead, buffer.Length - totalRead);
                    if (bytesRead == 0)
                        break;
                    totalRead += bytesRead;
                }
                return buffer;
            }
        }







    }



    public class Chat //AES256-GCM based encryption with key turning
    {
        //The sections shows are manuals on how to use the library; this will be in a fancy github wiki later

        #region Ideaology
        //One of my hardest scripts, but this has key turning in it (Constnatly making an encryption key available to everyone that's part of the group)
        //First, the leader creates a Kyber public private key pair and the public key is shared
        //Everyone uses the public key to create a key encapsulation, this is our session key
        //We encrypt the session key using AES256GCM and give it to everyone
        //Everyone signs their key using Dilithium, then when a message is sent we always verify it
        //(Done)

        //When a message is sent, we encrypt the message with the current version of the session key
        //A nonce is created/signed for every message (contains a counter, the username, previous session key and message hash)
        //Automatically we know the user is the user if the nonce is able to be both decrypted and read
        //(Done)

        //The session key is evolved with SHAKE256
        //After an interval (could be time or amount of messages), we create a new kyber key, with dilithium used for authenticity (rotation)


        //The below will be handled in PariahNetworking (AKA Spire)

        //If someone was removed or left, we reauthenticate everyone who is active in the last hour
        //If someone is added or talks, they go through SectionA (public/private key)
        //Instead of rotating and switching everyone, it might be worth it to store user references as their name + their lave/join amount + rotation
        //This way, instead of doing complex and intensive things we can just make sure the user needs a new key if they rejoin
        //If they leave, others can still then see their messages without someone being able to act like they're them and stuff



        //When someone new joins or someone is removed, we simply rotate with them

        //Offline messages are handled as session keys are stored on a sender's device
        //The keys are then given to the recepient when they're back, with the public kyber key for delivery, signed with dilitium

        //We have an action function that handles roles, messages, etc.
        //Also need CRDT and Audit Log with both being used to verify a sent in session
        //I'm not sure if for searching for messages and stuff it'll use Homomorphic Encryption or something yet

        #endregion

        #region SectionA Example

        //var leaderKeyPair = Keys.Intiiate();
        //share the public key with the group, hold the private key

        //Each member does var encapsulated = Keys.CreateSecret(leaderPublicKey);
        //Share the encapsulated.text with the leader, store the session key leader, leader checks all verificatiosn with VerifySignature()

        //The header does Keys.CreateSecretTwo(leaderPrivateKey, encryptedSessionKeyFromMember); once, save it to a dictionary with (memberID, encryptedsessionkey)
        //To create a good session key, let's use PasswordGenerator.GeneratePassword(32, true, true, true, true).ToSecureString(true); BUT we aren't done yet
        //Now we use   SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(true)(), recoverykey).ConvertToString(true)();    and we share the string with the user

        //The user decrypts the string (Turn it to SimpleAESEncryption.AESEncryptedText first) to get the shared session key

        //When sending out a message, we sign with the private key and send it to the others using CreateSignature()

        //We verify the signature with VerifySignature() when accepting a message, the input is the nonce referenced in the dilithium section

        #endregion

        #region SectionB2

        //It's important to create a simple, yet capable pipeline for files; we want to ensure the data is protected, comes from who it says it comes from and isn't tampered
        //We will use AES256GCM, Kyber and Blake3 Respectively

        //User creates a message struct with a construted MessageData and AttachmentData function; remember to use PackFiles() and UnpackFiles()
        //Add more detail later
        //Create function to decrypt MessageData and AttachmentData later

        #endregion


        public class MessageData
        {
            // Unique ID for the message
            public string MessageId { get; }

            // Name of the sender (could be a bot name or user display name, use the technical version, for example spire would be "Kirito@AnIncarnatingRadius.XYZ" or something)
            public string SenderName { get; }

            // Content of the message
            public string Content { get; }

            public DateTime Timestamp { get; }

            // Flag indicating whether the message was sent by a bot
            public bool IsBot { get; }

            // ID of the channel the message was sent in (could be used for group chat, channels, etc.)
            public string ChannelId { get; }

            //The last key to be used before the rotation
            public string PreviousKey { get; }

            //The number of rotations done
            public int Rotation { get; }



            //Content is the message
            public MessageData(string messageId, string senderName, string content, DateTime timestamp, bool isBot, string channelId, string previouskey, int rotation, SecureString SessionKey)
            {
                MessageId = messageId;
                SenderName = senderName;

                Content = Walker.Crypto.SimpleAESEncryption.Encrypt(content, SessionKey).ToString();

                Timestamp = timestamp;
                IsBot = isBot;
                ChannelId = channelId;
                PreviousKey = previouskey;
                Rotation = rotation;

            }

            public override string ToString()
            {
                return string.Join("\n",
                    $"MessageId: {MessageId}",
                    $"SenderName: {SenderName}",
                    $"Content: {Content}",
                    $"Timestamp: {Timestamp:yyyy-MM-dd HH:mm:ss}",
                    $"IsBot: {IsBot}",
                    $"ChannelId: {ChannelId}",
                    $"PreviousKey: {PreviousKey}",
                    $"Rotation: {Rotation}");
            }

            public static MessageData FromString(string formattedString, SecureString ChatKey)
            {
                var lines = formattedString.Split(new[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
                string messageId = lines[0].Substring(11);
                string senderName = lines[2].Substring(12);
                string content = lines[3].Substring(9);
                DateTime timestamp = DateTime.Parse(lines[4].Substring(11));
                bool isBot = bool.Parse(lines[5].Substring(8));
                string channelId = lines[6].Substring(11);
                string previousKey = lines[7].Substring(13);
                int rotation = int.Parse(lines[8].Substring(10));

                return new MessageData(messageId, senderName, content, timestamp, isBot, channelId, previousKey, rotation, ChatKey);
            }


        }     //This gets hashed, we encrypt the message within as well


        public class Message
        {

            //The sender of the messge, the rest won't be plain (If this is tampered, it'll be instantly noticeable when trying to decrypt)
            public string SenderID { get; }
            public MessageData Data { get; }
            public AttachmentData MediaData { get; }

            public byte[] Sign { get; } //The message sign with Blake3, make a method later


            public Message(string SenderID, MessageData Data, AttachmentData MediaData)
            {
                this.SenderID = SenderID;
                this.Data = Data;
                this.MediaData = MediaData;

            }



        }         //Optimally you should be using IPS (InterPlanetary File System) for sharing files decentralized, then you can reference it like www.aincrad.xyz/usermedia/path-goes-here


        public class AttachmentData     //We use Blake3 to handle verifying hashes 
        {
            //By this point, the file should have been compressed and hashed with Blake3

            public string SenderId { get; }

            //The string should be the IPS file name, using the chatroom directory we go to the cooresponding object folder on the object bin
            //The second string should be PackedFile turned into a string

            public Dictionary<string, string> FileHashes { get; set; } = new Dictionary<string, string>(); 

            //The string should be the IPS file name, using the chatroom directory we go to the cooresponding object folder on the object bin
            //The bytes are the blake3 hash, we know it will always be 32 bytes long
            public Dictionary<string, byte[]> Files { get; set; } = new Dictionary<string, byte[]>();

            public AttachmentData(string senderID, List<string> FileNames, SecureString secretkey, List<byte[]> privatekey)
            {
                this.SenderId = senderID;

                var dict = new Dictionary<string, byte[]>();

                int i = 0; //Call me old school
                
                foreach(string Filename in FileNames)
                {
                    var name = Walker.Crypto.SimpleAESEncryption.Encrypt(Filename, secretkey).ToString();

                    dict.Add(name, privatekey[i]);

                    i++;
                }

            }
           
        }





    }



    public class Merger //Handles syncing versions
    {

    }

}

