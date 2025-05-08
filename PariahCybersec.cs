using System.Security.Cryptography;
using System.Text;
using Walker.Crypto;
using Org.BouncyCastle.Security;
using static Pariah_Cybersecurity.DataHandler.SaltAndHashing;
using JObject = Newtonsoft.Json.Linq.JObject;
using JsonConvert = Newtonsoft.Json.JsonConvert;
using Konscious.Security.Cryptography;
using File = System.IO.File;
using System.Text.Json;
using System.Reflection;
using Newtonsoft.Json.Linq;
using System.Runtime.InteropServices;
using System.Diagnostics;
using static Walker.Crypto.SimpleAESEncryption;

using WISecureData;

using SecureData = WISecureData.SecureData;


//We no longer use SimpleAESEncryption because it does not adhere to AES256
//It also encrypts everything at once instead of in chunks, which is a HUGE problem memory wise

//We keep the names the same to make using our new code seamless


namespace Pariah_Cybersecurity
{

    public class PasswordGenerator
    {
        public static string GeneratePassword(int length, bool includeLowercase, bool includeUppercase,
            bool includeDigits, bool includeSpecialChars)
        {
            var passBuilder = new StringBuilder();


            if (length < 1) throw new ArgumentException("Password length must be greater than 0.");

            if (!includeLowercase && !includeUppercase && !includeDigits && !includeSpecialChars) throw new ArgumentException("Invalid generation inputs.");

            string LowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
            string UppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            string Digits = "0123456789";
            string SpecialChars = "!@#$%^&*()-_=+[]{}|;:',.<>?";

            string finalCharset = default;

            if (includeLowercase)
                finalCharset += LowercaseLetters;
            if (includeUppercase)
                finalCharset += UppercaseLetters;
            if (includeDigits)
                finalCharset += Digits;
            if (includeSpecialChars)
                finalCharset += SpecialChars;

            int maxRange = finalCharset.Length - 1;


            for (int i = 0; i < length; i++)
            {
                int val = RNGCSP.RollDice((byte)maxRange) - 1;
                passBuilder.Append(finalCharset[val]);
            }

            string generatedPass = passBuilder.ToString();

            return generatedPass;



        }

    }

    public class DataHandler
    {


        //Based off https://github.com/LifeandStyleMedia/UniversalSave, this has a method to easily create encrypted JSON and NBT style files

        public static class JSONDataHandler
        {

            public struct PariahJSON
            {
                public string FileName { get; private set; }
                public string FilePath { get; internal set; }
                public JObject Data { get; private set; }

                public PariahJSON(string fileName, string filePath, JObject data)
                {
                    FileName = fileName;
                    FilePath = filePath;
                    Data = data;
                }
            }


            public static async Task CreateJsonFile(string Filename, string FileLocation, JObject defaultData)
            {
                try
                {
                    //Check program ability to create file at location (location+name)
                    string finalPathLocation = Path.Combine(FileLocation, Filename + ".json");

                    if (Directory.Exists(FileLocation) == false) { throw new Exception("The file directory does not exist."); }

                    if (File.Exists(finalPathLocation)) { throw new Exception($"File with name already exists in directory, filepath is {finalPathLocation}."); }

                    var data = await BinaryConverter.NCObjectToByteArrayAsync<JObject>(defaultData);

                    await EasyPQC.WriteAllBytesAsync(finalPathLocation, data, null);

                }
                catch (Exception ex)
                {
                    throw new Exception($"An error occurred while saving the file: {ex.Message}", ex);
                }

            }


            public static async Task<PariahJSON> LoadJsonFile(string Filename, string FileLocation)
            {
                try
                {
                    // Check program ability to create file at location (location+name)  
                    string finalPathLocation = Path.Combine(FileLocation, Filename + ".json");

                    if (!Directory.Exists(FileLocation))
                    {
                        throw new Exception("The file directory does not exist.");
                    }

                    if (!File.Exists(finalPathLocation))
                    {
                        throw new Exception("File does not exist");
                    }

                    var file = await FileAsync.ReadAllBytes(finalPathLocation); // Remember the bytes are already JSON  

                    // Deserialize the byte array into a JObject  
                    var data = await BinaryConverter.NCByteArrayToObjectAsync<JObject>(file);

                    PariahJSON pariahJSON = new PariahJSON(Filename, FileLocation, data);

                    return pariahJSON;
                }
                catch
                {
                    throw new Exception("An error has occurred when reading the file. Please check your file reading permissions.");
                }
            }

            //Add conditionals later(?)

            public static async Task<PariahJSON> AddToJson<T>(PariahJSON JsonData, string dataName, object data, SecureData? Key)
            {
                JObject editedData = JsonData.Data;

                if (Key == null)
                {
                    Key = "skibidi".ToSecureData();
                }

                var newJsonData = await DataEncryptions.PackData<T>(data, (SecureData)Key);

                editedData.Add(dataName, newJsonData);

                PariahJSON finalPJ = new PariahJSON(JsonData.FileName, JsonData.FilePath, editedData);

                return finalPJ;

            }

            public static PariahJSON DeletefromJson(PariahJSON JsonData, string dataName)
            {
                JObject editedData = JsonData.Data;

                editedData.Remove(dataName);

                PariahJSON finalPJ = new PariahJSON(JsonData.FileName, JsonData.FilePath, editedData);

                return finalPJ;
            }

            public static async Task<PariahJSON> UpdateJson<T>(PariahJSON JsonData, string dataName, object data, SecureData? Key)
            {
                JObject editedData = JsonData.Data;

                editedData.Remove(dataName);


                if (Key == null)
                {
                    Key = "skibidi".ToSecureData();
                }

                var newJsonData = await DataEncryptions.PackData<T>(data, (SecureData)Key);

                editedData.Add(dataName, newJsonData);

                PariahJSON finalPJ = new PariahJSON(JsonData.FileName, JsonData.FilePath, editedData);

                return finalPJ;
            }

            public static async Task<object> GetVariable<T>(PariahJSON JsonData, string dataName, SecureData? Key)
            {
                JObject editedData = JsonData.Data;

                if (!editedData.TryGetValue(dataName, out var token) || token.Type != JTokenType.String)
                    throw new Exception($"Invalid or missing string for key '{dataName}'.");

                string item = token.Value<string>()!;

                if (Key == null)
                {
                    Key = "skibidi".ToSecureData();
                }

                var returnObject = await DataEncryptions.UnpackData(item, (SecureData)Key);

                return returnObject;
            }

            public static async Task<bool> CheckIfVariableExists(PariahJSON JsonData, string dataName)
            {
                JObject editedData = JsonData.Data;
                if (editedData.TryGetValue(dataName, out var token))
                {
                    return token.Type == JTokenType.String;
                }
                return false;
            }


            public static async Task SaveJson(PariahJSON JsonData)
            {
                JObject source = JsonData.Data;
                string Filename = JsonData.FileName;
                string FileLocation = JsonData.FilePath;

                try
                {
                    //Check program ability to create file at location (location+name)
                    string finalPathLocation = Path.Combine(FileLocation, Filename + ".json");

                    if (Directory.Exists(FileLocation) == false) { throw new Exception("The file directory does not exist."); };

                    if (File.Exists(finalPathLocation) == false) { throw new Exception("File with name does not existt in directory"); };

                    //Now that we checked those conditionals, let's update the JSON!

                    var data = await BinaryConverter.NCObjectToByteArrayAsync<JObject>(JsonData.Data);

                    await EasyPQC.WriteAllBytesAsync(finalPathLocation, data, null);

                }

                catch (Exception ex)
                {
                    throw new Exception($"An error occurred while saving the file: {ex.Message}", ex);
                }
            }




        }


        public static class SaltAndHashing
        {

            public struct PasswordCheckData
            {
                public string SaltKey { get; set; }
                public string HashKey { get; set; }

                public PasswordCheckData(string saltkey, string hashKey)
                {
                    SaltKey = saltkey;
                    HashKey = hashKey;
                }
            }



            public class PasswordHandler
            {
                private static readonly SecureRandom CryptoRandom = new SecureRandom();

                public static async Task<PasswordCheckData> GeneratePasswordHashAsync(SecureData password, int iterations = 4, int saltByteSize = 64, int hashByteSize = 128)
                {
                    return await Task.Run(async () =>
                    {
                        byte[] saltBytes = new byte[saltByteSize];
                        CryptoRandom.NextBytes(saltBytes);

                        var hash = await Argon2_GetHashAsync(password, saltBytes, iterations, hashByteSize);

                        var passcheckdata = new PasswordCheckData(
                            Convert.ToBase64String(saltBytes),
                            Convert.ToBase64String(hash)
                        );

                        return passcheckdata;
                    });
                }

                public static async Task<bool> ValidatePasswordAsync(SecureData password, PasswordCheckData passValues, int iterations = 4, int hashByteSize = 128)
                {
                    return await Task.Run(async () =>
                    {
                        string saltAsBase64 = passValues.SaltKey;
                        string hashAsBase64 = passValues.HashKey;

                        byte[] saltBytes = Convert.FromBase64String(saltAsBase64);
                        byte[] expectedHashBytes = Convert.FromBase64String(hashAsBase64);

                        var computedHashBytes = await Argon2_GetHashAsync(password, saltBytes, iterations, hashByteSize);

                        return SlowEquals(expectedHashBytes, computedHashBytes);
                    });
                }

                private static async Task<byte[]> Argon2_GetHashAsync(SecureData password, byte[] salt, int iterations, int hashByteSize)
                {
                    return await Task.Run(() =>
                    {
                        var bytes = UTF8Encoding.UTF8.GetBytes(password.ConvertToString());

                        var argon2id = new Argon2id(bytes)
                        {
                            Salt = salt,
                            DegreeOfParallelism = 1,
                            Iterations = iterations,
                            MemorySize = 8192
                        };

                        return argon2id.GetBytes(hashByteSize);
                    });
                }


                private static bool SlowEquals(byte[] a, byte[] b)
                {
                    uint diff = (uint)a.Length ^ (uint)b.Length;
                    for (int i = 0; i < a.Length && i < b.Length; i++)
                        diff |= (uint)(a[i] ^ (uint)b[i]);
                    return diff == 0;
                }

            }

        }





        //Thank you to https://stackoverflow.com/questions/34950611/how-to-create-a-pbkdf2-sha256-password-hash-in-c-sharp-bouncy-castle for BouncyCastleHashing, I should stop being lazy and add summaries too
  
        //Integrate logic from UserAuth


        //Great for non JSON files but recommended for advanced users, I personally use this with NBT
        //NGL Deepseek clutched the FWEAK up with this part since I couldn't get it right
        public static class DataEncryptions
        {
            // Shared options for both serialization and deserialization
            private static readonly JsonSerializerOptions _jsonOpts = new()
            {
                IncludeFields = true
            };

            public static async Task<string> PackData<T>(object data, SecureData Key)
            {
                byte[] payloadBytes = await BinaryConverter.NCObjectToByteArrayAsync<T>((T)data);
                var wrapper = (typeof(T).AssemblyQualifiedName!, payloadBytes);

                // Serialize with fields enabled
                byte[] wrapperBytes = JsonSerializer.SerializeToUtf8Bytes(wrapper, _jsonOpts);

                string wrapperB64 = Convert.ToBase64String(wrapperBytes);
                var encrypted = SimpleAESEncryption.Encrypt(wrapperB64, Key);
                return encrypted.ToString();
            }

            public static async Task<object> UnpackData(string data, SecureData Key)
            {
                try
                {
                    var aesEncryptedText = SimpleAESEncryption.AESEncryptedText.FromUTF8String(data);
                    string wrapperB64 = SimpleAESEncryption.Decrypt(aesEncryptedText, Key)
                                                      .ConvertToString();

                    byte[] wrapperBytes = Convert.FromBase64String(wrapperB64);

                    // Deserialize with fields enabled
                    var wrapper = JsonSerializer.Deserialize<(string, byte[])>(
                                      wrapperBytes, _jsonOpts);

                    string typeName = wrapper.Item1;
                    byte[] payload = wrapper.Item2;

                    Type type = Type.GetType(typeName)
                                ?? throw new Exception($"Could not resolve type '{typeName}'.");

                    var method = typeof(BinaryConverter)
                        .GetMethod(nameof(BinaryConverter.NCByteArrayToObjectAsync),
                                   BindingFlags.Public | BindingFlags.Static)!
                        .MakeGenericMethod(type);

                    var task = (Task)method.Invoke(null, new object[] { payload, null, CancellationToken.None })!;
                    await task.ConfigureAwait(false);

                    return task.GetType().GetProperty("Result")!.GetValue(task)!;
                }

                catch (Exception ex)
                {
                    throw new Exception(ex.ToString());
                }
            }
        }


        public static class SecretManager
        {

            //Note; this all says "Public" but this can all be used anywhere; in the AccountsWithSessions, it's used to manage user secrets per directory
            //Should go without saying but if you update or migrate secrets, you should have your own systems made around ensuring and updating possibly related values

            public class PublicKeyFile
            {
                public string SecretName { get; internal set; }
                public string SecretPath { get; internal set; }

                public PublicKeyFile(string secretName, string secretPath)
                {
                    SecretName = secretName;
                    SecretPath = secretPath;
                }

            }

            public class PublicKeyFileInit
            {
                public string SecretName { get; internal set; }
                public SecureData Value { get; internal set; }
                public SecureData? SecretPath { get; internal set; } //Do NOT include a name here

                public PublicKeyFileInit(string secretName, SecureData? secretPath, SecureData value)
                {
                    SecretName = secretName;
                    SecretPath = secretPath;
                    Value = value;
                }

            }

            //Creates a password bank; this doesn't hold the data itself but rather references to mentioned data
            //PublicKeyFiles = string Name, string Keyfile Location (Encrypted?)
            //Account = Just use Accounts.CreateUser/Login

            //PublicDecryptKey should be a SecureData as an input, not a String
            public async static Task CreateBank(string BankDirectory, string BankName, List<PublicKeyFileInit>? PublicKeys, string? PublicDecryptKey)
            {
                //You can (and should) generally create PublicDecryptKey as null, unless you are making a software specific "public" key (which might be better just being a secret but I digress
                //Whenever PublicKeyFileInit.SecretPath is null, the BankDirectory is used; PublicKeyFileInit.Key is automatically encrypted with PubliccDecryptKey

                //First up let's set PublicDecryptKey
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); //We will use the motherboard's serial key as the publicdecryptkey by default
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                //Now we see if a Bank with the same name exists at the path we selected

                if (await CheckIfBankExists(BankDirectory, BankName))
                {
                    throw new Exception($"The Bank Directory Already Exists At {Path.Combine(BankDirectory, $"{BankName}.json")}");
                }

                //At this point, we know the bank doesn't exist, let's create it! We will use publicKeys to initialize, but this list is completely optional

                var pKeysForSaving = new List<PublicKeyFile>();

                if (PublicKeys == null || PublicKeys.Count == 0)
                {
                    //Do nothing and continue
                }

                else
                {
                    foreach (var item in PublicKeys)
                    {
                        //First create the variables 

                        SecureData savepath = BankDirectory.ToSecureData();

                        if (item.SecretPath != null)
                        {
                            savepath = (SecureData)item.SecretPath;
                        }

                        var finalPath = SimpleAESEncryption.Encrypt(savepath.ConvertToString(), keyToUseAsPassword);

                        pKeysForSaving.Add(new PublicKeyFile(item.SecretName, finalPath.ToString()));

                        //Create the file

                        var secretData = new JObject
                        {
                            ["Secret Name"] = item.SecretName,
                        };

                        await JSONDataHandler.CreateJsonFile(item.SecretName, savepath.ConvertToString(), secretData);

                        var loadedJson2 = await JSONDataHandler.LoadJsonFile(
                            item.SecretName,
                            savepath.ConvertToString()
                        );

                        var sValue = await JSONDataHandler.AddToJson<string>(loadedJson2, "Secret Value", SimpleAESEncryption.Encrypt(item.Value.ConvertToString(), keyToUseAsPassword).ToString(), keyToUseAsPassword);

                        var pneuValue = await JSONDataHandler.AddToJson<string>(sValue, "Pneumentations", SimpleAESEncryption.Encrypt(0.ToString(), keyToUseAsPassword).ToString(), keyToUseAsPassword);

                        await JSONDataHandler.SaveJson(pneuValue);

                    }

                }

                //Create the bank save file


                var bankOpeningData = new JObject
                {
                    ["Bank Name"] = BankName
                };

                await JSONDataHandler.CreateJsonFile(BankName, BankDirectory, bankOpeningData);

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var jsonWithPublicKeyFileList = await JSONDataHandler.AddToJson<List<PublicKeyFile>>(loadedJson, "PublicSecrets", pKeysForSaving, keyToUseAsPassword);

                await JSONDataHandler.SaveJson(jsonWithPublicKeyFileList);

            }

            public static async Task<bool> CheckIfBankExists(string BankDirectory, string BankName)
            {
                string secretManagerPath = Path.Combine(BankDirectory, $"{BankName}.json");
                return File.Exists(secretManagerPath);
            }

            //Gets a public secret by finding the path within the secret bank, going to the file and decrypting the value, add SecretDecryptKey to everything
            public static async Task<SecureData> GetPublicSecret(string BankDirectory, string BankName, string PublicSecretName, string? PublicDecryptKey, string? SecretDecryptKey)
            {
                //First up let's set PublicDecryptKey
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); //We will use the motherboard's serial key as the publicdecryptkey by default
                }

                if (SecretDecryptKey == null)
                {
                    SecretDecryptKey = PublicDecryptKey;
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();
                var keyToUseAsSecretPassword = SecretDecryptKey.ToSecureData();

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                PublicKeyFile? secretToGet = null;

                foreach (var pair in listOfPublicKeyFile)
                {
                    if (pair.SecretName == PublicSecretName)
                    {
                        secretToGet = pair;
                        break;
                    }

                }



                if (secretToGet == null)
                {
                    throw new Exception("Secret with key does not exist.");
                }


                //Now to get the actual value from the main file
                //IDK why I have to do all this to make the thing work, but it does so i'm not going to change it

                var finalPath = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(secretToGet.SecretPath), keyToUseAsSecretPassword).ConvertToString();

                var jsonWithKey = await JSONDataHandler.LoadJsonFile(secretToGet.SecretName, finalPath);


                var returnedVal = (string)await JSONDataHandler.GetVariable<string>(jsonWithKey, "Secret Value", keyToUseAsSecretPassword);

                var decryptedVal = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(returnedVal), keyToUseAsSecretPassword);

                return decryptedVal;


            }

            public static async Task<int> GetSecretRound(string BankDirectory, string BankName, string PublicSecretName, string? PublicDecryptKey)
            {
                //First up let's set PublicDecryptKey
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); //We will use the motherboard's serial key as the publicdecryptkey by default
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                PublicKeyFile? secretToGet = null;

                foreach (var pair in listOfPublicKeyFile)
                {

                    if (pair.SecretName == PublicSecretName)
                    {
                        secretToGet = pair;
                        break;
                    }

                }

                if (secretToGet == null)
                {
                    throw new Exception("Secret with key does not exist.");
                }


                //Now to get the actual value from the main file
                //IDK why I have to do all this to make the thing work, but it does so i'm not going to change it

                var finalPath = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(secretToGet.SecretPath), keyToUseAsPassword).ConvertToString();

                var jsonWithKey = await JSONDataHandler.LoadJsonFile(secretToGet.SecretName, finalPath);


                var returnedVal = (string)await JSONDataHandler.GetVariable<string>(jsonWithKey, "Pneumentations", keyToUseAsPassword);

                var decryptedVal = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(returnedVal), keyToUseAsPassword);

                var decryptedValParsedToInt = int.Parse(decryptedVal.ConvertToString());

                return decryptedValParsedToInt;


            }

            public static async Task AddPublicSecret(string BankDirectory, string BankName, PublicKeyFileInit PublicSecret, string? PublicDecryptKey)
            {
                //First up let's set PublicDecryptKey
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); //We will use the motherboard's serial key as the publicdecryptkey by default
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                //Now to add the actual value to the main file


                SecureData savepath = BankDirectory.ToSecureData();

                if (PublicSecret.SecretPath != null)
                {
                    savepath = (SecureData)PublicSecret.SecretPath;
                }

                var finalPath = SimpleAESEncryption.Encrypt(savepath.ConvertToString(), keyToUseAsPassword);

                listOfPublicKeyFile.Add(new PublicKeyFile(PublicSecret.SecretName, finalPath.ToString()));

                //Create the file

                var secretData = new JObject
                {
                    ["Secret Name"] = PublicSecret.SecretName,
                };

                await JSONDataHandler.CreateJsonFile(PublicSecret.SecretName, savepath.ConvertToString(), secretData);

                var fileToSave = await JSONDataHandler.UpdateJson<List<PublicKeyFile>>(loadedJson, "PublicSecrets", listOfPublicKeyFile, keyToUseAsPassword);

                await JSONDataHandler.SaveJson(fileToSave);

                var loadedJson2 = await JSONDataHandler.LoadJsonFile(
                    PublicSecret.SecretName,
                    savepath.ConvertToString()
                );

                var sValue = await JSONDataHandler.AddToJson<string>(loadedJson2, "Secret Value", SimpleAESEncryption.Encrypt(PublicSecret.Value.ConvertToString(), keyToUseAsPassword).ToString(), keyToUseAsPassword);

                var pneuValue = await JSONDataHandler.AddToJson<string>(sValue, "Pneumentations", SimpleAESEncryption.Encrypt(0.ToString(), keyToUseAsPassword).ToString(), keyToUseAsPassword);

                await JSONDataHandler.SaveJson(pneuValue);

            }

            public static async Task DeletePublicSecret(string BankDirectory, string BankName, string PublicSecretName, string? PublicDecryptKey)
            {
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); // Use motherboard serial as default key
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                //Load the main bank JSON
                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                //Find the specific secret
                PublicKeyFile? secretToDelete = null;

                foreach (var pair in listOfPublicKeyFile)
                {

                    if (pair.SecretName == PublicSecretName)
                    {
                        secretToDelete = pair;
                        break;
                    }

                }

                if (secretToDelete == null)
                {
                    throw new Exception($"No public secret found with the name '{PublicSecretName}'.");
                }

                //Remove the secret from the list
                listOfPublicKeyFile.Remove(secretToDelete);

                //Delete the actual secret file
                var decryptedPath = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(secretToDelete.SecretPath), keyToUseAsPassword).ConvertToString();
                var filePath = Path.Combine(decryptedPath, $"{PublicSecretName}.json");

                if (File.Exists(filePath))
                {
                    File.Delete(filePath);
                }

                //Save the updated list back into the bank file
                var fileToSave = await JSONDataHandler.UpdateJson<List<PublicKeyFile>>(loadedJson, "PublicSecrets", listOfPublicKeyFile, keyToUseAsPassword);
                await JSONDataHandler.SaveJson(fileToSave);
            }

            public static async Task<List<string>> GetAllSecretNames(string BankDirectory, string BankName, string? PublicDecryptKey)
            {
                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); // Use motherboard serial as default key
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                List<string> listOfNames = new List<string>();

                foreach (var item in listOfPublicKeyFile)
                {
                    listOfNames.Add(item.SecretName);
                }

                return listOfNames;

            }

            //Enter a value into newSalt if you want to reset pneumentations to 0 with a new salt
            public static async Task<SecureData> RotateSecret(string BankDirectory, string BankName, string PublicSecretName, string? salt, string? PublicDecryptKey, string? newSalt)
            {
                var secretToRotate = await GetPublicSecret(BankDirectory, BankName, PublicSecretName, PublicDecryptKey, PublicDecryptKey);

                var pqClass = new EasyPQC.Rotation();

                if (PublicDecryptKey == null)
                {
                    PublicDecryptKey = await DeviceIdentifier.GetBoardSerialAsync(); //We will use the motherboard's serial key as the publicdecryptkey by default
                }

                var keyToUseAsPassword = PublicDecryptKey.ToSecureData();

                if (salt == null && newSalt == null)
                {
                    salt = keyToUseAsPassword.ToString();
                }

                else if (newSalt != null)
                {
                    salt = newSalt;
                }

                int rotations = 0;

                if (newSalt == null)
                {
                    rotations = await GetSecretRound(BankDirectory, BankName, PublicSecretName, PublicDecryptKey);

                }

                var secretRotated = await pqClass.RotateKey(secretToRotate, rotations, salt);

                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                PublicKeyFile? secretToGet = null; //Atp we are sure this won't be null, else the first call we did with GetPublicSecret() would've been borked

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", keyToUseAsPassword);

                foreach (var pair in listOfPublicKeyFile)
                {

                    if (pair.SecretName == PublicSecretName)
                    {
                        secretToGet = pair;
                        break;
                    }

                }

                var finalPath = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(secretToGet.SecretPath), keyToUseAsPassword).ConvertToString();

                var jsonWithKey = await JSONDataHandler.LoadJsonFile(secretToGet.SecretName, finalPath);

                var encryptedSecret = SimpleAESEncryption.Encrypt(secretRotated, keyToUseAsPassword).ToString();

                var encryptedPneu = SimpleAESEncryption.Encrypt(rotations.ToString(), keyToUseAsPassword).ToString();

                var jsonWithUpdatedSecret = await JSONDataHandler.UpdateJson<string>(jsonWithKey, "Secret Value", encryptedSecret, keyToUseAsPassword);

                var jsonWithUpdatedPneu = await JSONDataHandler.UpdateJson<string>(jsonWithUpdatedSecret, "Pneumentations", encryptedSecret, keyToUseAsPassword);

                await JSONDataHandler.SaveJson(jsonWithUpdatedPneu);

                return secretRotated.ToSecureData();

            }

            //Migrate is a WIP function which should NOT be used yet
            public static async Task MigratePublicSecrets(string BankDirectory, string BankName, Dictionary<string, (SecureData? OldPassword, SecureData? NewPassword, string NewPath)> secretMigrations, string newBankDirPath,
                string? NewFileDirectoryPath, SecureData OldPublicDecryptKey, SecureData? NewPublicDecryptKey)
            {
                // Use default key if none provided
                if (NewPublicDecryptKey == null)
                {
                    var temp = await DeviceIdentifier.GetBoardSerialAsync();
                    NewPublicDecryptKey = temp.ToSecureData();
                }

                // Load main bank file using OldPublicDecryptKey
                var loadedJson = await JSONDataHandler.LoadJsonFile(BankName, BankDirectory);

                var listOfPublicKeyFile = (List<PublicKeyFile>)await JSONDataHandler.GetVariable<List<PublicKeyFile>>(loadedJson, "PublicSecrets", OldPublicDecryptKey);


                //We are going to assume that either OldPassword or OldPublicDecryptKey will be given, else this will break
                foreach (var secretFile in listOfPublicKeyFile)
                {
                    if (!secretMigrations.TryGetValue(secretFile.SecretName, out var migrationInfo))
                    {
                        //Remove the item from the list and continue
                        listOfPublicKeyFile.Remove(secretFile);
                    }

                    var (oldPassword, newPassword, newPath) = migrationInfo;


                    //If oldPassword is null, we will instead use OldPublicDecryptKey

                    if (oldPassword == null)
                    {
                        oldPassword = OldPublicDecryptKey;
                    }

                    //If the newPassword is null, we will use NewPublicDecryptKey instead

                    if (newPassword == null)
                    {
                        newPassword = NewPublicDecryptKey;
                    }

                    //Let's get the file with the stuff we need
                    var decryptedPath = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(secretFile.SecretPath), (SecureData)oldPassword).ConvertToString();
                    var jsonWithKey = await JSONDataHandler.LoadJsonFile(secretFile.SecretName, decryptedPath);

                    // Decrypt the actual values
                    var encryptedSecretValueStr = (string)await JSONDataHandler.GetVariable<string>(jsonWithKey, "Secret Value", oldPassword);
                    var encryptedPneumentationsStr = (string)await JSONDataHandler.GetVariable<string>(jsonWithKey, "Pneumentations", oldPassword);

                    //Remember, the strings we saved are SimpleAESEncryption.AESEncryptedText converted to text with the .ToString() method
                    var decryptedSecretValue = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(encryptedSecretValueStr), (SecureData)oldPassword);
                    var decryptedPneumentations = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(encryptedPneumentationsStr), (SecureData)oldPassword);

                    // Parse decrypted values
                    string secretString = decryptedSecretValue.ConvertToString();
                    int pneumentationCount = int.Parse(decryptedPneumentations.ConvertToString());

                    // Encrypt with new password
                    var newEncryptedSecret = SimpleAESEncryption.Encrypt(secretString, (SecureData)newPassword).ToString();
                    var newEncryptedPneumentation = SimpleAESEncryption.Encrypt(pneumentationCount.ToString(), (SecureData)newPassword).ToString();

                    // If NewPath is empty, we use newBankDirectoryPath
                    var newSavePath = newPath ?? NewFileDirectoryPath; //WE LOVE ?? CHECKS

                    var updatedJson = new JObject
                    {
                        ["Secret Name"] = secretFile.SecretName,

                    };

                    await JSONDataHandler.CreateJsonFile(secretFile.SecretName, NewFileDirectoryPath, updatedJson);

                    var loadedJson2 = await JSONDataHandler.LoadJsonFile(secretFile.SecretName, NewFileDirectoryPath);

                    var sValue = await JSONDataHandler.AddToJson<string>(loadedJson2, "Secret Value", newEncryptedSecret, newPassword);

                    var pneuValue = await JSONDataHandler.AddToJson<string>(sValue, "Pneumentations", newEncryptedPneumentation, newPassword);

                    await JSONDataHandler.SaveJson(pneuValue);

                    // Update the path in bank

                    var newEncryptedPath = SimpleAESEncryption.Encrypt(newSavePath, (SecureData)newPassword);
                    secretFile.SecretPath = SimpleAESEncryption.Encrypt(newEncryptedPath.ToString(), (SecureData)newPassword).ToString();

                }

                // Save updated bank as a new bank in a new location
                var bankName = loadedJson.FileName;
                await CreateBank(newBankDirPath, bankName, null, NewPublicDecryptKey.ToString());
                var fileToUserp = await JSONDataHandler.LoadJsonFile(BankName, newBankDirPath);
                var finalizedFile = await JSONDataHandler.UpdateJson<List<PublicKeyFile>>(fileToUserp, "PublicSecrets", listOfPublicKeyFile, NewPublicDecryptKey);

                await JSONDataHandler.SaveJson(finalizedFile);
            }









        }




        class DeviceIdentifier
        {
            public static async Task<string> GetBoardSerialAsync()
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    return await RunCommandAsync("wmic", "baseboard get serialnumber");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    return await RunCommandAsync("cat", "/sys/class/dmi/id/board_serial");
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    return await RunCommandAsync("ioreg", "-l | awk -F'\"' '/IOPlatformSerialNumber/ {print $4}'");
                }
                else
                {
                    return "Unsupported OS";
                }
            }

            private static async Task<string> RunCommandAsync(string fileName, string arguments)
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        psi.FileName = fileName;
                        psi.Arguments = arguments;
                    }
                    else
                    {
                        psi.FileName = "/bin/bash";
                        psi.Arguments = $"-c \"{fileName} {arguments}\"";
                    }

                    using var process = new Process { StartInfo = psi };
                    process.Start();

                    var output = await process.StandardOutput.ReadToEndAsync();
                    await process.WaitForExitAsync();

                    var result = output.Trim().Split('\n');
                    return result.Length > 0 ? result[^1].Trim() : "Unknown";
                }
                catch (Exception ex)
                {
                    return $"Error: {ex.Message}";
                }
            }

        }


        public class DataRequest
        {

            public static class SecuritySettings
            {
                public static SecureData PublicKey { get; private set; }
                public static double ExpiryDuration { get; private set; }
                public static double TrustedExpiryDuration { get; private set; }
                public static int FailRecoveryCheck { get; private set; }
                public static double TimeToNextRecovery { get; private set; }

                // Static constructor
                static SecuritySettings()
                {
                    PublicKey = "Default".ToSecureData();
                    ExpiryDuration = 540;
                    TrustedExpiryDuration = 20160;
                    FailRecoveryCheck = 5;
                    TimeToNextRecovery = 20;
                }

                public static void SetPublicKey(string newKey)
                {
                    PublicKey.Dispose(); // Don't forget to clean up old SecureData!
                    PublicKey = newKey.ToSecureData();
                }

                public static void SetExpiryDuration(double minutes)
                {
                    ExpiryDuration = minutes;
                }

                public static void SetTrustedExpiryDuration(double minutes)
                {
                    TrustedExpiryDuration = minutes;
                }

                public static void SetFailRecoveryCheck(int count)
                {
                    FailRecoveryCheck = count;
                }

                public static void SetTimeToNextRecovery(double minutes)
                {
                    TimeToNextRecovery = minutes;
                }
            }

            public class DirectoryData
            {
                public string CompanyPath { get; set; }
                public string MainServicePath { get; set; }
                public string ServiceParent { get; set; }
                public string Author { get; set; }
                public string Software { get; set; }
                public string UserSharedResources { get; set; }
                public string UserFolder { get; set; }
                public string ExePath { get; set; }

                public string Program { get; set; }


                public DirectoryData() { } // Required for deserialization

                public DirectoryData(
                    string companyPath,
                    string mainServicePath,
                    string serviceParent,
                    string author,
                    string software,
                    string userSharedResources,
                    string userFolder,
                    string exePath,
                    string program)
                {
                    CompanyPath = companyPath;
                    MainServicePath = mainServicePath;
                    ServiceParent = serviceParent;
                    Author = author;
                    Software = software;
                    UserSharedResources = userSharedResources;
                    UserFolder = userFolder;
                    ExePath = exePath;
                    Program = program;
                }
            }

            public class EncryptedTier
            {
                public byte[] SignedEncryptedTier { get; set; }
                public string EncryptedTierPass { get; set; }
                public byte[] SignedTierPass { get; set; }

                public EncryptedTier() { } // Required for deserialization

                public EncryptedTier(byte[] signedEncryptedTier, string encryptedTierPass, byte[] signedTierPass)
                {
                    SignedEncryptedTier = signedEncryptedTier;
                    EncryptedTierPass = encryptedTierPass;
                    SignedTierPass = signedTierPass;
                }
            }

            //Example function to get the path of the exe file for the program that called this

            public static async Task<string?> GetExecutablePathAsync(string command)
            {
                var isWindows = OperatingSystem.IsWindows();
                var fileName = isWindows ? "where" : "which";

                var psi = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = command,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                try
                {
                    using var process = Process.Start(psi);
                    if (process == null)
                        return null;

                    var output = await process.StandardOutput.ReadLineAsync();
                    await process.WaitForExitAsync();

                    return string.IsNullOrWhiteSpace(output) ? null : output.Trim();
                }
                catch
                {
                    return null;
                }
            }

            public static async Task<bool> IsFileWithinDirectoryAsync(string filePath, string baseDirectory)
            {
                return await Task.Run(() =>
                {
                    try
                    {
                        var fullFilePath = Path.GetFullPath(filePath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                        var fullBasePath = Path.GetFullPath(baseDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

                        return fullFilePath.StartsWith(fullBasePath, StringComparison.OrdinalIgnoreCase);
                    }
                    catch
                    {
                        return false;
                    }
                });
            }





            //Helper function
            static string MakeRelativeFromAuthor(string fullPath, string author)
            {
                fullPath = Path.GetFullPath(fullPath).Replace('\\', '/');
                author = author.Trim('/');

                int index = fullPath.IndexOf("/" + author + "/", StringComparison.OrdinalIgnoreCase);
                if (index == -1) return fullPath; // fallback to full path if not found

                return fullPath.Substring(index + 1); // +1 to remove leading slash
            }


            public async Task<DirectoryData> GetPaths(SecureData identifier, string software, string author,
                string programName, string serviceParent)
            {

                string companyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), author); //Zakstar

                string mainServicePath = Path.Combine(companyPath, serviceParent); //Zakstar/GunGaleOnline

                string specificProgram = Path.Combine(mainServicePath, software); //Zakstar/GunGaleOnline/TournamentOfBullets   Holds a json with all users (Sinon, LLENN, DeathGun, Etc.)

                string userSharedResources = Path.Combine(specificProgram, "UserSharedResources"); //Zakstar/GunGaleOnline/TournamentOfBullets/UserSharedResources   Shared across specific subprogram
                
                var identifierToUse = identifier.ConvertToString();

                var exePath = await GetExecutablePathAsync(programName);

                string userProgramFolder = Path.Combine(mainServicePath, identifierToUse); //Zakstar/GunGaleOnline/TournamentOfBullets/Sinon       Data shared between the subprograms (Specifically for this user)

                var relativeMainProgramPath = MakeRelativeFromAuthor(mainServicePath, author); //Zakstar/GGO/TOB

                var newDirectoryFolder = new DirectoryData(companyPath, mainServicePath, specificProgram, author, software, userSharedResources, userProgramFolder, exePath, programName);

                return newDirectoryFolder;

            }

            public async Task<bool> CheckMainPathValidity(DirectoryData data, SecureData? PublicKey)
            {
                try
                {



                    var loadedJSON = await JSONDataHandler.LoadJsonFile("CORE", data.MainServicePath);

                    var loadedPubKey = (Dictionary<string, byte[]>)await JSONDataHandler.GetVariable<Dictionary<string, byte[]>>(loadedJSON, "Public Key", PublicKey);

                    var loadedMotherPath = (byte[])await JSONDataHandler.GetVariable<byte[]>(loadedJSON, "signedMother", PublicKey);

                    var relativeMainProgramPath = MakeRelativeFromAuthor(data.MainServicePath, data.Author); //Zakstar/GGO/TOB

                    var loadedMotherPathCheck = await EasyPQC.Signatures.VerifySignature(loadedPubKey, loadedMotherPath, relativeMainProgramPath);


                    return loadedMotherPathCheck;
                }
                catch (Exception ex)
                {
                    throw new Exception($"An error occured: {ex}");
                }
            }

            public async Task<bool> ValidateProgram(DirectoryData data, string programName, SecureData? PublicKey)
            {

                var programPath = await GetExecutablePathAsync(programName);

                var returnVal = await IsFileWithinDirectoryAsync(programPath, data.MainServicePath);

                return returnVal;


            }



            public async Task<SecureData> CreateNewSystem(string username, SecureData identifier, SecureData password, string software, string author, 
                string exePath, string serviceParent, int tiers, SecureData? PublicKey)
            {

                if (PublicKey == null)
                {
                    var temp = await DeviceIdentifier.GetBoardSerialAsync();
                    PublicKey = temp.ToSecureData();
                }


                #region Basic Paths
                //First create the proper paths
                string companyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), author); //Zakstar

                string mainServicePath = Path.Combine(companyPath, serviceParent); //Zakstar/GunGaleOnline

                string specificProgram = Path.Combine(mainServicePath, software); //Zakstar/GunGaleOnline/TournamentOfBullets   Holds a json with all users (Sinon, LLENN, DeathGun, Etc.)

                string userSharedResources = Path.Combine(specificProgram, "UserSharedResources"); //Zakstar/GunGaleOnline/TournamentOfBullets/UserSharedResources   Shared across specific subprogram

                //Do these paths exist?
                if (!Directory.Exists(companyPath))
                {
                    Directory.CreateDirectory(companyPath);
                }

                if (!Directory.Exists(mainServicePath))
                {
                    Directory.CreateDirectory(mainServicePath);
                }

                if (!Directory.Exists(specificProgram))
                {
                    Directory.CreateDirectory(specificProgram);
                }

                if (!Directory.Exists(userSharedResources))
                {
                    Directory.CreateDirectory(userSharedResources);
                }

                #endregion

                var identifierToUse = identifier.ConvertToString();


                string userProgramFolder = Path.Combine(mainServicePath, identifierToUse); //Zakstar/GunGaleOnline/TournamentOfBullets/Sinon       Data shared between the subprograms (Specifically for this user)



                var relativeMainProgramPath = MakeRelativeFromAuthor(mainServicePath, author); //Zakstar/GGO/TOB

                //First we will create a CORE service for this program

                await JSONDataHandler.CreateJsonFile("CORE", mainServicePath, new JObject { });

                var loadedJson = await JSONDataHandler.LoadJsonFile("CORE", mainServicePath);

                var keys = await EasyPQC.Signatures.CreateKeys();

                //Signatures

                var signedMotherPath = await EasyPQC.Signatures.CreateSignature(keys.Item2, relativeMainProgramPath); //Signs the main software path

                var signedCreatedBy = await EasyPQC.Signatures.CreateSignature(keys.Item2, author);

                var savedPubKey = await JSONDataHandler.AddToJson<Dictionary<string, byte[]>>(loadedJson, "Public Key", keys.Item1, PublicKey); 

                var savedMotherPath = await JSONDataHandler.AddToJson<byte[]>(savedPubKey, "signedMother", signedMotherPath, PublicKey);

                await JSONDataHandler.SaveJson(savedMotherPath);

                //Secret bank for Gun Gale Online

                await SecretManager.CreateBank(userSharedResources, "SecretBank", null, PublicKey.ToString());

                //Manasger of Permissions and Allowed Software

                // Think of tiers as levels in a company; the manager has access to everything employee and manager level,
                // while the director has access to director, manager, and employee level data. Each higher tier inherits
                // permissions from the lower ones, like a hierarchy of access control.

                Dictionary<string, SecureData> tiervals = new Dictionary<string, SecureData>();

                for (int i = 0; i < tiers; i++)
                {
                    var tierPass = PasswordGenerator.GeneratePassword(32, true, true, true, true).ToSecureData();
                    tiervals.Add(i.ToString(), tierPass);
                }


                //And now to save these tiers in their own file; you technically cam make thousands but I highly suggest putting it to something reasonable like 10 max
                //This is pretty much like a KeyCard given to a program BTW; since we know the password to the program and the tiers, we can simply keep reference of it in a file

                Dictionary<string, EncryptedTier> encryptedTiers = new Dictionary<string, EncryptedTier>(); //tierVal (tierValSign, TierEncryptedKey, tierEncKeySign)
                //Signed with the same signature from earlier

                foreach (var item in tiervals)
                {
                    var itemval = item.Value.ConvertToString();


                    var encTierPass = SimpleAESEncryption.Encrypt(item.Value.ConvertToString(), (SecureData)PublicKey).ToString();
                    var signedTierPass = await EasyPQC.Signatures.CreateSignature(keys.Item2, item.Value.ConvertToString());
                    var signedEncTier = await EasyPQC.Signatures.CreateSignature(keys.Item2, item.Key);

                    encryptedTiers.Add(item.Key, new EncryptedTier (signedEncTier, encTierPass, signedTierPass));


                }



                await JSONDataHandler.CreateJsonFile("Data Tiers", mainServicePath, new JObject { });

                var jsonToHaveTiers = await JSONDataHandler.LoadJsonFile("Data Tiers", mainServicePath);

                var jsonWithTiers = await JSONDataHandler.UpdateJson<Dictionary<string, EncryptedTier>>(jsonToHaveTiers, "Data Tiers", encryptedTiers, PublicKey);

                await JSONDataHandler.SaveJson(jsonWithTiers);


                //And now to create the way in which programs can add files
                //For now, we are going to make a file which has what programs are allowed to make an account as well as the permissions it has
                //We will also make it so the programs can "Login" to the respective system
                //And finally the session key container for holding session tokens


                await JSONDataHandler.CreateJsonFile("Allowed Programs", mainServicePath, new JObject { });

                var loadedAllowedPrograms = await JSONDataHandler.LoadJsonFile("Allowed Programs", mainServicePath);

                var jsonWithLoadedAllowedPrograms = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Allowed Programs", new Dictionary<string, SecureData>(), PublicKey); //Software name, Software Tier ID (Software Name + ID)

                var jsonWithBlacklistedPrograms = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(jsonWithLoadedAllowedPrograms, "Blacklisted Programs", new Dictionary<string, SecureData>(), PublicKey); //Software name, Software Tier ID (Software Name + ID)



                await JSONDataHandler.SaveJson(jsonWithBlacklistedPrograms);


                var acSessions = new AccountsWithSessions();





                //Guess what? WE USE THE SYSTEM FROM AccountsWithSessions, we are literally pasting it here with a few minor changes (Adding a thing)

                // Initialize an empty list of AccountData

                await SetupFiles(mainServicePath);

                var mainAccReturn = await CreateUser(username, password, mainServicePath);

                return mainAccReturn;


            }

            public async Task<SecureData> CreateNewApp(string username, SecureData password, string Directory, DirectoryData directories, string tier, SecureData? PublicKey)
            {

                var properDirectoryCheck = await CheckMainPathValidity(directories, PublicKey);

                var mainServicePath = directories.MainServicePath;

                var loadedAllowedPrograms = await JSONDataHandler.LoadJsonFile("Allowed Programs", mainServicePath);

                var jsonWithBlacklistedPrograms = (Dictionary<string, SecureData>) await JSONDataHandler.GetVariable<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Blacklisted Programs", PublicKey); //Software name, Software Tier ID (Software Name + ID)

                //Should still be secure, can be better

                var isProgramBlacklisted = jsonWithBlacklistedPrograms.ContainsKey(directories.Software) || jsonWithBlacklistedPrograms.ContainsValue(directories.ExePath.ToSecureData());

                if (isProgramBlacklisted)
                {
                    throw new Exception("This program is blacklisted.");
                }

                var allowedProgramsList = (Dictionary<string, SecureData>) await JSONDataHandler.GetVariable<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Allowed Programs", PublicKey); //Software name, Software Tier ID (Software Name + ID)


                var jsonToHaveTiers = await JSONDataHandler.LoadJsonFile("Data Tiers", mainServicePath);

                var jsonWithTiers = (Dictionary<string, EncryptedTier>) await JSONDataHandler.GetVariable<Dictionary<string, EncryptedTier>>(jsonToHaveTiers, "Data Tiers", PublicKey);




                var hasTier = jsonWithTiers.ContainsKey(tier);

                if (!hasTier)
                {
                    throw new Exception("The requested tier does not exist.");
                }



                var itemval = jsonWithTiers[tier];

                var decTierPass = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(itemval.EncryptedTierPass), (SecureData)PublicKey).ToString();

                var signedTierPass = itemval.SignedTierPass;
                var signedEncTier = itemval.SignedEncryptedTier;


                var loadedCOREJson = await JSONDataHandler.LoadJsonFile("CORE", mainServicePath);

                var pubKey = (Dictionary<string, byte[]>) await JSONDataHandler.GetVariable<Dictionary<string, byte>>(loadedCOREJson, "Public Key", PublicKey);

                //Has errors, needs to be fixed but should still be secure

                var verifiedTierPass = await EasyPQC.Signatures.VerifySignature(pubKey, signedEncTier, tier);

                //var verifiedTierKey = await EasyPQC.Signatures.VerifySignature(pubKey, signedTierPass, tier);


                if (!verifiedTierPass)
                {



                    throw new Exception("The tier information does not match the signature.");
                }

                var encProgramTier = SimpleAESEncryption.Encrypt(tier, (SecureData)PublicKey).ToString().ToSecureData();

                allowedProgramsList.Add(directories.Software, encProgramTier);

                var JsonWithUpdatedAppsList = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Allowed Programs", allowedProgramsList, PublicKey);

                await JSONDataHandler.SaveJson(JsonWithUpdatedAppsList);

                //And now create directories/Account

                var mainAccReturn = await CreateUser(username, password, mainServicePath);

                return mainAccReturn;


            }

            public async Task AddToBlacklist (string softwareName, ConnectedSessionReturn connSession, string mainServicePath, SecureData PublicKey)
            {
                await ValidateSession(connSession, PublicKey);

                var loadedAllowedPrograms = await JSONDataHandler.LoadJsonFile("Allowed Programs", mainServicePath);

                var jsonWithBlacklistedPrograms = (Dictionary<string, SecureData>)await JSONDataHandler.GetVariable<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Blacklisted Programs", PublicKey); //Software name, Software Tier ID (Software Name + ID)

                bool varExists = false;


                foreach (var item in jsonWithBlacklistedPrograms)
                {
                    if (item.Key == softwareName)
                    {
                        varExists = true;
                        break;
                    }

   
                }

                if (varExists)
                {
                    throw new Exception("This program is already blacklisted.");
                }


                jsonWithBlacklistedPrograms.Add(softwareName, mainServicePath.ToSecureData()); 

                var jsonToSave = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Blacklisted Programs", jsonWithBlacklistedPrograms, PublicKey); //Software name, Software Tier ID (Software Name + ID)

                await JSONDataHandler.SaveJson(jsonToSave);
            }

            public async Task RemoveFromBlacklist (string softwareName, ConnectedSessionReturn connSession, string mainServicePath, SecureData PublicKey)
            {
                await ValidateSession(connSession, PublicKey);

                var loadedAllowedPrograms = await JSONDataHandler.LoadJsonFile("Allowed Programs", mainServicePath);

                var jsonWithBlacklistedPrograms = (Dictionary<string, SecureData>)await JSONDataHandler.GetVariable<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Blacklisted Programs", PublicKey); //Software name, Software Tier ID (Software Name + ID)

                bool varExists = false;


                foreach (var item in jsonWithBlacklistedPrograms)
                {
                    if (item.Key == softwareName)
                    {
                        varExists = true;
                        break;
                    }


                }

                if (!varExists)
                {
                    throw new Exception("This program does not exist.");
                }


                jsonWithBlacklistedPrograms.Remove(softwareName);

                var jsonToSave = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Blacklisted Programs", jsonWithBlacklistedPrograms, PublicKey); //Software name, Software Tier ID (Software Name + ID)

                await JSONDataHandler.SaveJson(jsonToSave);
            }


            public async Task RemoveAccount(string softwareName, ConnectedSessionReturn connSession, string mainServicePath, SecureData PublicKey)
            {
                await ValidateSession(connSession, PublicKey);

                var loadedAllowedPrograms = await JSONDataHandler.LoadJsonFile("Allowed Programs", mainServicePath);

                var allowedProgramsList = (Dictionary<string, SecureData>)await JSONDataHandler.GetVariable<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Allowed Programs", PublicKey); //Software name, Software Tier ID (Software Name + ID)


                bool varExists = false;

                foreach (var item in allowedProgramsList)
                {
                    if (item.Key == softwareName)
                    {
                        varExists = true;
                        break;
                    }

                }

                if (!varExists)
                {
                    throw new Exception("This program app does not exist.");
                }


                allowedProgramsList.Remove(softwareName);

                var updatedProgramsList = await JSONDataHandler.UpdateJson<Dictionary<string, SecureData>>(loadedAllowedPrograms, "Allowed Programs", allowedProgramsList, PublicKey); //Software name, Software Tier ID (Software Name + ID)

                await JSONDataHandler.SaveJson(updatedProgramsList);

            }

            public async Task VerifySessionIntegrity(DirectoryData data, ConnectedSessionReturn connSession, string mainServicePath, SecureData PublicKey)
            {

                var mpValidity = await CheckMainPathValidity(data, PublicKey);

                var sessIntegrity = await ValidateSession(connSession, PublicKey);

                if (!mpValidity || !sessIntegrity)
                {
                    throw new Exception("The integrity session has failed. You have been logged off.");
                }

            }









            //Note, this is literally just the Account With Sessions System copy pasted here, but I put it here for the SecuritySettings thing specifically
            //If you update AccountWithSessions, you can completely CopyPaste it here, just remember to update the SecuritySettings too (It's at the top of this class)

            //You should use the logic from the account system when it comes to adding/removing data software!



            //You should use SimpleAESEncryption here, with the returned string being the password!
            //I suggest wrapping it around another layer of password obfuscation; for example 
            //Get User Password
            //Use as AES256 Key on a generated password (Which will be your local encryption/decryption key)
            //Encrypt the generated password using a second generated password (recovery key) and store that somewhere
            //When the user decides to encrypt everything, unlock the generated password using the recovery key
            //Generate a new passkey
            //Decrypt all data and reencrypt it using the new key

            #region Account System


            public class ActiveSession
            {
                public string Username { get; set; }
                public string SessionID { get; set; }
                public string SessionKey { get; set; }
                public string Expiry { get; set; }
                public string IsTrusted { get; set; }
                public string ChecksAndLastTry { get; set; }


                public ActiveSession() { }
                public ActiveSession(string username, string softwareID, string sessionKey, string expiry, string isTrusted, string checksAndLastTry)
                {
                    Username = username;
                    SessionID = softwareID;
                    SessionKey = sessionKey;
                    Expiry = expiry;
                    IsTrusted = isTrusted;
                    ChecksAndLastTry = checksAndLastTry;

                }
            }

            public class ConnectedSessionReturn
            {

                public SecureData Username { get; private set; }
                public SecureData SessionKey { get; private set; }
                public SecureData SessionID { get; private set; }

                public SecureData Directory { get; private set; }

                public ConnectedSessionReturn() { }

                public ConnectedSessionReturn(string username, string sessionKey, string sessionID, SecureData directory)
                {
                    Username = username.ToSecureData();
                    SessionKey = sessionKey.ToSecureData();
                    SessionID = sessionID.ToSecureData();
                    Directory = directory;
                }
            }

            public class ReturnCreateUser
            {
                public ConnectedSessionReturn sessionReturn { get; private set; }
                public SecureData RecoveryKey { get; private set; }

                public ReturnCreateUser() { }

                public ReturnCreateUser(ConnectedSessionReturn sessionReturn, SecureData recoveryKey)
                {
                    this.sessionReturn = sessionReturn;
                    RecoveryKey = recoveryKey;
                }

            }






     
            public class AccountData
            {
                public string Username { get; set; }
                public PasswordCheckData Password { get; set; }
                public string DataEncryptionKey { get; set; }
                public string RecoveryDataKey { get; set; }


                public AccountData() { } // Required for deserialization

                public AccountData(string username, PasswordCheckData password, string dataEncryptionKey, string recoveryDataKey)
                {
                    Username = username;
                    Password = password;
                    DataEncryptionKey = dataEncryptionKey;
                    RecoveryDataKey = recoveryDataKey;

                }
            }



            //This system uses JSON.DataHandler instead of pack and unpacking, whicch is the better way to go about things!




            public async Task SetupFiles(string directory)
            {
                // Initialize an empty list of AccountData
                List<AccountData> accountsList = new List<AccountData>();

                // Use your JSONDataHandler to create the file
                await JSONDataHandler.CreateJsonFile("Users", directory, new JObject { });

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", directory);

                var jsonWithData = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJSON, "AccountsList", accountsList, SecuritySettings.PublicKey);

                var jsonWithActiveSessionData = await JSONDataHandler.UpdateJson<List<ActiveSession>>(jsonWithData, "Sessions", new List<ActiveSession>(), SecuritySettings.PublicKey);

                // Insert your own logic below! Just be sure to change JsonWithData to whatever variable should be there now

                await JSONDataHandler.SaveJson(jsonWithActiveSessionData);
            }

            public async Task<SecureData> CreateUser(string username, SecureData password, string Directory) //Return recovery key  
            {
                // 1. Create base user representation  
                // 2. Save salted/hashed password  
                // 3. Generate and save key used to encrypt information  

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory);

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                // Check if the username already exists  
                if (UserList.Any(user => user.Username == username))
                {
                    throw new Exception($"The username '{username}' already exists. Please choose a different username.");
                }

                var encryptedpass = await PasswordHandler.GeneratePasswordHashAsync(password);

                SecureData encryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var recoverykey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var encryptedrecoverable = SimpleAESEncryption.Encrypt(recoverykey.ConvertToString(), encryptionkey).ToString();

                var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), password).ToString();




                var finalizeddata = new AccountData(username, encryptedpass, encryptedkey, encryptedrecoverable);

                UserList.Add(finalizeddata);

                var updatedJson = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJson, "AccountsList", UserList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedJson);

                return recoverykey;
            }

            public async Task<SecureData> LoginCore(string username, string Directory, SecureData password) //Return file encryption key  
            {
                try
                {
                    var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory); // Ensure this is awaited  

                    List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);




                    AccountData currentLoginTrial = default;
                    bool userfound = false;

                    foreach (AccountData item in UserList)
                    {
                        if (item.Username == username)
                        {
                            currentLoginTrial = item;
                            userfound = true;
                            break;
                        }
                    }

                    if (userfound)
                    {
                        var passtocheck = currentLoginTrial.Password;
                        bool correctpass = await PasswordHandler.ValidatePasswordAsync(password, passtocheck);

                        if (correctpass)
                        {
                            var encryptionkey = SimpleAESEncryption.AESEncryptedText.FromUTF8String(currentLoginTrial.DataEncryptionKey);
                            var finalreturnval = SimpleAESEncryption.Decrypt(encryptionkey, password);

                            if (finalreturnval == null)
                            {
                                throw new Exception("Decryption failed. The returned key is null.");
                            }

                            return finalreturnval;
                        }
                        else
                        {
                            throw new Exception($"The username or password is incorrect.");
                        }
                    }
                    else
                    {
                        throw new Exception($"User '{username}' not found.");
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"An error has occurred: {ex.Message}", ex);
                }
            }


            public async Task<(SecureData, ConnectedSessionReturn)> LoginUser(string username, string Directory, SecureData password, bool IsTrusted) //Return file encryption key  
            {
                //We can actually use the same Login Logic from the generic "accounts" system!

                var aesKey = await LoginCore(username, Directory, password);

                //Now we will set a session, it will be ConnectedSessionReturn

                var sessionKey = PasswordGenerator.GeneratePassword(64, true, true, true, true);

                var sessionID = PasswordGenerator.GeneratePassword(32, true, true, true, true);

                var encSessionKey = SimpleAESEncryption.Encrypt(sessionKey, aesKey).ToString();

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", Directory);

                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                DateTime Expiry = DateTime.UtcNow;

                if (IsTrusted)
                {
                    Expiry = Expiry.AddMinutes(SecuritySettings.TrustedExpiryDuration);
                }

                else
                {
                    Expiry = Expiry.AddMinutes(SecuritySettings.ExpiryDuration);
                }

                var isTrusted = Expiry.ToString("o") + "|" + IsTrusted.ToString();

                var encIsTrusted = SimpleAESEncryption.Encrypt(isTrusted, SecuritySettings.PublicKey).ToString();

                var checkData = (0.ToString() + "|" + DateTime.UtcNow.ToString("o"));


                var encCheckData = SimpleAESEncryption.Encrypt(checkData, SecuritySettings.PublicKey).ToString();

                var editedSessList = ActiveSessList;

                editedSessList.Add(new ActiveSession(username, sessionID, encSessionKey, Expiry.ToString("o"), encIsTrusted, encCheckData));


                var jsonWithActiveSessionData = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", editedSessList, SecuritySettings.PublicKey);


                await JSONDataHandler.SaveJson(jsonWithActiveSessionData);

                var connReturnVals = new ConnectedSessionReturn(username, sessionKey, sessionID, Directory.ToSecureData());

                return (aesKey, connReturnVals);


            }

            public async Task<bool> ValidateSession(ConnectedSessionReturn connSession, SecureData decryptKey)
            {
                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());
                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                try
                {
                    ActiveSession? sess = null;

                    foreach (var item in ActiveSessList)
                    {
                        if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                        {
                            sess = item;
                            break;
                        }
                    }

                    if (sess == null)
                    {
                        throw new Exception("A session with this ID and user does not exist.");
                    }

                    DateTime parsedTimeCheck = DateTime.Parse(sess.Expiry, null, System.Globalization.DateTimeStyles.AssumeUniversal);

                    if (DateTime.UtcNow > parsedTimeCheck)
                    {
                        // Session expired, remove it
                        ActiveSessList.Remove(sess);
                        var updatedJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                        await JSONDataHandler.SaveJson(updatedJson);

                        return false;
                    }
                    else
                    {
                        // Validate IsTrusted field and Session Key
                        var isTrustedDecrypted = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(sess.IsTrusted), SecuritySettings.PublicKey); //Function will auto stop if bad
                        var parts = isTrustedDecrypted.ConvertToString().Split('|');

                        var isKeyGood = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(sess.SessionKey), decryptKey); //Function will auto stop if bad


                        if (isKeyGood.ConvertToString() != connSession.SessionKey.ConvertToString())
                        {
                            // Tampering detected
                            ActiveSessList.Remove(sess);
                            var updatedCancelJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                            await JSONDataHandler.SaveJson(updatedCancelJson);

                            throw new Exception("The data for this session does not match and the token has been invalidated.");
                        }

                        if (parts.Length != 2)
                        {
                            throw new Exception("Invalid session trusted data format.");
                        }

                        var expiryString = parts[0];
                        bool isTrusted = bool.Parse(parts[1]);

                        if (expiryString != sess.Expiry)
                        {
                            // Tampering detected
                            ActiveSessList.Remove(sess);
                            var updatedCancelJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                            await JSONDataHandler.SaveJson(updatedCancelJson);

                            throw new Exception("The data for this session does not match and the token has been invalidated.");
                        }

                        // Extend session
                        DateTime newExpiry = DateTime.UtcNow.AddMinutes(isTrusted ? SecuritySettings.TrustedExpiryDuration : SecuritySettings.ExpiryDuration);
                        var newIsTrustedData = newExpiry.ToString("o") + "|" + isTrusted.ToString();
                        var newEncIsTrusted = SimpleAESEncryption.Encrypt(newIsTrustedData, SecuritySettings.PublicKey).ToString();

                        // Replace old session
                        ActiveSessList.Remove(sess);
                        ActiveSessList.Add(new ActiveSession(sess.Username, sess.SessionID, sess.SessionKey, newExpiry.ToString("o"), newEncIsTrusted, sess.ChecksAndLastTry));

                        var updatedSessionJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                        await JSONDataHandler.SaveJson(updatedSessionJson);

                        return true;
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Session validation error: {ex.Message}", ex);
                }
            }

            public async Task LogoutUser(ConnectedSessionReturn connSession, SecureData decryptKey)
            {

                await ValidateSession(connSession, decryptKey); //You don't really need to verify the bool, it should throw an exception automatically

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                try
                {
                    ActiveSession? sess = null;

                    foreach (var item in ActiveSessList)
                    {
                        if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                        {
                            sess = item;
                        }
                    }

                    ActiveSessList.Remove(sess);
                    var updatedJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                    await JSONDataHandler.SaveJson(updatedJson);
                }

                catch (Exception ex)
                {
                    throw new Exception($"An Error Has Occured: {ex}");
                }


            }
            //Remember to wipe the connSession and decryptKey

            public async Task RemoveAccount(ConnectedSessionReturn connSession, SecureData decryptKey)
            {


                await ValidateSession(connSession, decryptKey); //You don't really need to verify the bool, it should throw an exception automatically

                await LogoutUser(connSession, decryptKey);

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                var matchedUser = UserList.FirstOrDefault(user => user.Username == connSession.Username.ConvertToString());


                if (matchedUser == null)
                {
                    throw new Exception("This user does not exist.");
                }


                UserList.Remove(matchedUser);

                var updatedJson = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJson, "AccountsList", UserList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedJson);


            }


            public async Task ResetPassword(ConnectedSessionReturn connSession, SecureData decryptKey, SecureData NewPassword, SecureData RecoveryPass)
            {

                await ValidateSession(connSession, decryptKey);

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);
                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJson, "Sessions", SecuritySettings.PublicKey);


                AccountData? matchedUser = null;

                foreach (var user in UserList)
                {


                    if (user.Username == connSession.Username.ConvertToString())
                    {
                        matchedUser = user;
                        break; // Exit loop once a match is found
                    }
                }

                if (matchedUser == null)
                {
                    throw new Exception("This user does not exist.");
                }

                ActiveSession? matchedSess = null;

                foreach (var session in ActiveSessList)
                {

                    if (session.Username == connSession.Username.ConvertToString())
                    {
                        matchedSess = session;
                        break; // Exit loop once a match is found
                    }
                }

                if (matchedUser == null)
                {
                    throw new Exception("This session does not exist.");
                }

                var decryptedMatchedSessCALT = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(matchedSess.ChecksAndLastTry), SecuritySettings.PublicKey).ConvertToString();

                var decryptedRecoveryKey = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(matchedUser.RecoveryDataKey), decryptKey).ConvertToString();

                var parts = decryptedMatchedSessCALT.Split('|');
                int number = int.Parse(parts[0]);
                DateTime time = DateTime.Parse(parts[1], null, System.Globalization.DateTimeStyles.RoundtripKind);

                //Decrypt all things in matchedUser
                if (decryptedRecoveryKey != RecoveryPass.ConvertToString() && !(number == SecuritySettings.FailRecoveryCheck || number == -1))
                {
                    if (number == -1 && time < DateTime.UtcNow)
                    {
                        var newUpdatedVal = ((0) + "|" + time.ToString("o"));
                        matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                        await JSONDataHandler.SaveJson(loadedJson);
                        throw new Exception("The recovery key is invalid, please try again.");

                    }

                    else if (number == -1 && time > DateTime.UtcNow)
                    {
                        var newUpdatedVal2 = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.Local);
                        throw new Exception($"The recovery key was invalid too many times, please try again at {newUpdatedVal2.ToString("yyyy-MM-dd HH:mm:ss")}");
                    }

                    else
                    {
                        var newUpdatedVal = ((number + 1) + "|" + time.ToString("o"));
                        matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                        await JSONDataHandler.SaveJson(loadedJson);
                        throw new Exception("The recovery key is invalid, please try again.");

                    }

                }

                else if (decryptedRecoveryKey != RecoveryPass.ConvertToString() && (number == SecuritySettings.FailRecoveryCheck - 1))
                {
                    time.AddMinutes(SecuritySettings.TimeToNextRecovery);
                    var newUpdatedVal = ((-1) + "|" + time.ToString("o"));
                    DateTime localTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.Local);
                    matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                    await JSONDataHandler.SaveJson(loadedJson);
                    throw new Exception($"The recovery key was invalid too many times, please try again at {localTime.ToString("yyyy-MM-dd HH:mm:ss")}");
                }

                else if (matchedUser.RecoveryDataKey == RecoveryPass.ConvertToString())
                {
                    var newUpdatedVal = ((0) + "|" + time.ToString("o"));
                    matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();
                    await JSONDataHandler.SaveJson(loadedJson);
                    //The key is right!
                }

                matchedUser.Password = await PasswordHandler.GeneratePasswordHashAsync(NewPassword);

                SecureData encryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var recoverykey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData(); //Return this

                matchedUser.RecoveryDataKey = SimpleAESEncryption.Encrypt(recoverykey.ConvertToString(), encryptionkey).ToString();

                var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), NewPassword).ToString();

                var checkData = 0.ToString() + "|" + DateTime.UtcNow.ToString("o");

                var encCheckData = SimpleAESEncryption.Encrypt(checkData, SecuritySettings.PublicKey).ToString();

                await JSONDataHandler.SaveJson(loadedJson);

                //Now to update the sessions (We remove them)

                var loadedActiveSessionsJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var UserRelatedSessions = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedActiveSessionsJSON, "Sessions", SecuritySettings.PublicKey);

                List<ActiveSession> sessions = new List<ActiveSession>();

                foreach (var item in UserRelatedSessions)
                {
                    if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                    {
                        sessions.Remove(item);
                    }
                }


                var updatedSessList = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedActiveSessionsJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedSessList);


            }

            public async Task<List<string>> GetAllUsernames(ConnectedSessionReturn connSession, SecureData decryptKey)
            {
                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var names = new List<string>();

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                foreach (var item in UserList)
                {
                    names.Add(item.Username);
                }

                return names;


            }



            #endregion










        }



        public class Accounts
        {

            internal SecureData PublicKey = "Default".ToSecureData();

            internal void ChangePublicKey(string NewVal)
            {
                PublicKey = NewVal.ToSecureData();
            }

            public class AccountData
            {
                public string Username { get; set; }
                public PasswordCheckData Password { get; set; }
                public string DataEncryptionKey { get; set; }
                public string RecoveryDataKey { get; set; }

                public AccountData() { } // Required for deserialization

                public AccountData(string username, PasswordCheckData password, string dataEncryptionKey, string recoveryDataKey)
                {
                    Username = username;
                    Password = password;
                    DataEncryptionKey = dataEncryptionKey;
                    RecoveryDataKey = recoveryDataKey;
                }
            }



            public async Task SetupFiles(string directory)
            {
                // Initialize an empty list of AccountData
                List<AccountData> accountsList = new List<AccountData>();

                // Use your JSONDataHandler to create the file
                await JSONDataHandler.CreateJsonFile("Users", directory, new JObject { });

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", directory);

                var jsonWithData = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJSON, "AccountsList", accountsList, PublicKey);

                // Insert your own logic below! Just be sure to change JsonWithData to whatever variable should be there now

                await JSONDataHandler.SaveJson(jsonWithData);
            }

            public async Task<SecureData> CreateUser(string username, SecureData password, string Directory) //Return recovery key  
            {
                // 1. Create base user representation  
                // 2. Save salted/hashed password  
                // 3. Generate and save key used to encrypt information  

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory);

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", PublicKey);

                // Check if the username already exists  
                if (UserList.Any(user => user.Username == username))
                {
                    throw new Exception($"The username '{username}' already exists. Please choose a different username.");
                }

                var encryptedpass = await PasswordHandler.GeneratePasswordHashAsync(password);

                SecureData encryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var recoverykey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var encryptedrecoverable = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), recoverykey).ToString();

                var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), password).ToString();

                var finalizeddata = new AccountData(username, encryptedpass, encryptedkey, encryptedrecoverable);

                UserList.Add(finalizeddata);

                var updatedJson = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJson, "AccountsList", UserList, PublicKey);

                await JSONDataHandler.SaveJson(updatedJson);

                return recoverykey;
            }


            public async Task<SecureData> LoginUser(string username, string Directory, SecureData password) //Return file encryption key  
            {
                try
                {
                    var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory); // Ensure this is awaited  

                    List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", PublicKey);




                    AccountData currentLoginTrial = default;
                    bool userfound = false;

                    foreach (AccountData item in UserList)
                    {
                        if (item.Username == username)
                        {
                            currentLoginTrial = item;
                            userfound = true;
                            break;
                        }
                    }

                    if (userfound)
                    {
                        var passtocheck = currentLoginTrial.Password;
                        bool correctpass = await PasswordHandler.ValidatePasswordAsync(password, passtocheck);

                        if (correctpass)
                        {
                            var encryptionkey = SimpleAESEncryption.AESEncryptedText.FromUTF8String(currentLoginTrial.DataEncryptionKey);
                            var finalreturnval = SimpleAESEncryption.Decrypt(encryptionkey, password);

                            if (finalreturnval == null)
                            {
                                throw new Exception("Decryption failed. The returned key is null.");
                            }

                            return finalreturnval;
                        }
                        else
                        {
                            throw new Exception($"The username or password is incorrect.");
                        }
                    }
                    else
                    {
                        throw new Exception($"User '{username}' not found.");
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"An error has occurred: {ex.Message}", ex);
                }
            }

            public async Task<SecureData> ResetPassword(string username, string Directory, SecureData newpassword, SecureData RecoveryPass)
            {
                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory);

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", PublicKey);

                AccountData currentLoginTrial = default;
                bool userfound = false;

                foreach (AccountData item in UserList)
                {
                    if (item.Username == username)
                    {
                        currentLoginTrial = item;
                        userfound = true;
                        break;
                    }
                }

                if (userfound)
                {

                    try
                    {

                        var recoverykeyaes = SimpleAESEncryption.AESEncryptedText.FromUTF8String(currentLoginTrial.RecoveryDataKey);
                        var encryptionkey = SimpleAESEncryption.Decrypt(recoverykeyaes, RecoveryPass);

                        //Had to make a note here, if this is right then we 

                        var encryptedpass = await PasswordHandler.GeneratePasswordHashAsync(newpassword);

                        SecureData newencryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                        var encryptedrecoverable = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), newencryptionkey).ToString();

                        var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), newpassword).ToString();

                        var finalizeddata = new AccountData(username, encryptedpass, encryptedkey, encryptedrecoverable);


                        //Now replace the user item

                        UserList.Remove(currentLoginTrial);

                        UserList.Add(finalizeddata);

                        var updatedJson = JSONDataHandler.UpdateJson<List<DataHandler.Accounts.AccountData>>(loadedJson, "AccountsList", UserList, PublicKey);

                        return newencryptionkey;

                    }


                    catch
                    {

                        throw new Exception($"The username or password is incorrect.");

                    }

                }

                else
                {
                    throw new Exception($"The username or password is incorrect.");
                }



            }

            //To "logout", just clear the SecureData return from Login User







        }


        public class AccountsWithSessions
        {

            public class ActiveSession
            {
                public string Username { get; set; }
                public string SessionID { get; set; }
                public string SessionKey { get; set; }
                public string Expiry { get; set; }
                public string IsTrusted { get; set; }
                public string ChecksAndLastTry { get;  set; }


                public ActiveSession() { }
                public ActiveSession(string username, string softwareID, string sessionKey, string expiry, string isTrusted, string checksAndLastTry)
                {
                    Username = username;
                    SessionID = softwareID;
                    SessionKey = sessionKey;
                    Expiry = expiry;
                    IsTrusted = isTrusted;
                    ChecksAndLastTry = checksAndLastTry;

                }
            }

            public class ConnectedSessionReturn
            {

                public SecureData Username { get; private set; }
                public SecureData SessionKey { get; private set; }
                public SecureData SessionID { get; private set; }

                public SecureData Directory { get; private set; }

                public ConnectedSessionReturn() { }

                public ConnectedSessionReturn(string username, string sessionKey, string sessionID, SecureData directory)
                {
                    Username = username.ToSecureData();
                    SessionKey = sessionKey.ToSecureData();
                    SessionID = sessionID.ToSecureData();
                    Directory = directory;
                }
            }

            public class ReturnCreateUser
            {
                public ConnectedSessionReturn sessionReturn { get; private set; }
                public SecureData RecoveryKey { get; private set; }

                public ReturnCreateUser() { }

                public ReturnCreateUser(ConnectedSessionReturn sessionReturn, SecureData recoveryKey)
                {
                    this.sessionReturn = sessionReturn;
                    RecoveryKey = recoveryKey;
                }

            }





            //You should use SimpleAESEncryption here, with the returned string being the password!
            //I suggest wrapping it around another layer of password obfuscation; for example 
            //Get User Password
            //Use as AES256 Key on a generated password (Which will be your local encryption/decryption key)
            //Encrypt the generated password using a second generated password (recovery key) and store that somewhere
            //When the user decides to encrypt everything, unlock the generated password using the recovery key
            //Generate a new passkey
            //Decrypt all data and reencrypt it using the new key
            public static class SecuritySettings
            {
                public static SecureData PublicKey { get; private set; }
                public static double ExpiryDuration { get; private set; }
                public static double TrustedExpiryDuration { get; private set; }
                public static int FailRecoveryCheck { get; private set; }
                public static double TimeToNextRecovery { get; private set; }

                // Static constructor
                static SecuritySettings()
                {
                    PublicKey = "Default".ToSecureData();
                    ExpiryDuration = 540;
                    TrustedExpiryDuration = 20160;
                    FailRecoveryCheck = 5;
                    TimeToNextRecovery = 20;
                }

                public static void SetPublicKey(string newKey)
                {
                    PublicKey.Dispose(); // Don't forget to clean up old SecureData!
                    PublicKey = newKey.ToSecureData();
                }

                public static void SetExpiryDuration(double minutes)
                {
                    ExpiryDuration = minutes;
                }

                public static void SetTrustedExpiryDuration(double minutes)
                {
                    TrustedExpiryDuration = minutes;
                }

                public static void SetFailRecoveryCheck(int count)
                {
                    FailRecoveryCheck = count;
                }

                public static void SetTimeToNextRecovery(double minutes)
                {
                    TimeToNextRecovery = minutes;
                }
            }


            public class AccountData
            {
                public string Username { get; set; }
                public PasswordCheckData Password { get; set; }
                public string DataEncryptionKey { get; set; }
                public string RecoveryDataKey { get; set; }


                public AccountData() { } // Required for deserialization

                public AccountData(string username, PasswordCheckData password, string dataEncryptionKey, string recoveryDataKey)
                {
                    Username = username;
                    Password = password;
                    DataEncryptionKey = dataEncryptionKey;
                    RecoveryDataKey = recoveryDataKey;

                }
            }



            //This system uses JSON.DataHandler instead of pack and unpacking, whicch is the better way to go about things!

            public async Task SetupFiles(string directory)
            {
                // Initialize an empty list of AccountData
                List<AccountData> accountsList = new List<AccountData>();

                // Use your JSONDataHandler to create the file
                await JSONDataHandler.CreateJsonFile("Users", directory, new JObject { });

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", directory);

                var jsonWithData = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJSON, "AccountsList", accountsList, SecuritySettings.PublicKey);

                var jsonWithActiveSessionData = await JSONDataHandler.UpdateJson<List<ActiveSession>>(jsonWithData, "Sessions", new List<ActiveSession>(), SecuritySettings.PublicKey);

                // Insert your own logic below! Just be sure to change JsonWithData to whatever variable should be there now

                await JSONDataHandler.SaveJson(jsonWithActiveSessionData);
            }

            public async Task<SecureData> CreateUser(string username, SecureData password, string Directory) //Return recovery key  
            {
                // 1. Create base user representation  
                // 2. Save salted/hashed password  
                // 3. Generate and save key used to encrypt information  

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory);

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                // Check if the username already exists  
                if (UserList.Any(user => user.Username == username))
                {
                    throw new Exception($"The username '{username}' already exists. Please choose a different username.");
                }

                var encryptedpass = await PasswordHandler.GeneratePasswordHashAsync(password);

                SecureData encryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var recoverykey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var encryptedrecoverable = SimpleAESEncryption.Encrypt(recoverykey.ConvertToString(), encryptionkey).ToString();

                var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), password).ToString();




                var finalizeddata = new AccountData(username, encryptedpass, encryptedkey, encryptedrecoverable);

                UserList.Add(finalizeddata);

                var updatedJson = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJson, "AccountsList", UserList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedJson);

                return recoverykey;
            }

            private async Task<SecureData> LoginCore(string username, string Directory, SecureData password) //Return file encryption key  
            {
                try
                {
                    var loadedJson = await JSONDataHandler.LoadJsonFile("Users", Directory); // Ensure this is awaited  

                    List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

     



                    AccountData currentLoginTrial = default;
                    bool userfound = false;

                    foreach (AccountData item in UserList)
                    {
                        if (item.Username == username)
                        {
                            currentLoginTrial = item;
                            userfound = true;
                            break;
                        }
                    }

                    if (userfound)
                    {
                        var passtocheck = currentLoginTrial.Password;
                        bool correctpass = await PasswordHandler.ValidatePasswordAsync(password, passtocheck);

                        if (correctpass)
                        {
                            var encryptionkey = SimpleAESEncryption.AESEncryptedText.FromUTF8String(currentLoginTrial.DataEncryptionKey);
                            var finalreturnval = SimpleAESEncryption.Decrypt(encryptionkey, password);

                            if (finalreturnval == null)
                            {
                                throw new Exception("Decryption failed. The returned key is null.");
                            }

                            return finalreturnval;
                        }
                        else
                        {
                            throw new Exception($"The username or password is incorrect.");
                        }
                    }
                    else
                    {
                        throw new Exception($"User '{username}' not found.");
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"An error has occurred: {ex.Message}", ex);
                }
            }


            public async Task<(SecureData, ConnectedSessionReturn)> LoginUser(string username, string Directory, SecureData password, bool IsTrusted) //Return file encryption key  
            {
                //We can actually use the same Login Logic from the generic "accounts" system!

                var aesKey = await LoginCore(username, Directory, password);

                //Now we will set a session, it will be ConnectedSessionReturn

                var sessionKey = PasswordGenerator.GeneratePassword(64, true, true, true, true);

                var sessionID = PasswordGenerator.GeneratePassword(32, true, true, true, true);

                var encSessionKey = SimpleAESEncryption.Encrypt(sessionKey, aesKey).ToString();

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", Directory);

                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                DateTime Expiry = DateTime.UtcNow;

                if (IsTrusted)
                {
                    Expiry = Expiry.AddMinutes(SecuritySettings.TrustedExpiryDuration);
                }

                else
                {
                    Expiry = Expiry.AddMinutes(SecuritySettings.ExpiryDuration);
                }

                var isTrusted = Expiry.ToString("o") + "|" + IsTrusted.ToString();

                var encIsTrusted = SimpleAESEncryption.Encrypt(isTrusted, SecuritySettings.PublicKey).ToString();

                var checkData = (0.ToString() + "|" + DateTime.UtcNow.ToString("o"));


                var encCheckData = SimpleAESEncryption.Encrypt(checkData, SecuritySettings.PublicKey).ToString();

                var editedSessList = ActiveSessList;

                editedSessList.Add(new ActiveSession(username, sessionID, encSessionKey, Expiry.ToString("o"), encIsTrusted, encCheckData));


                var jsonWithActiveSessionData = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", editedSessList, SecuritySettings.PublicKey);


                await JSONDataHandler.SaveJson(jsonWithActiveSessionData);

                var connReturnVals = new ConnectedSessionReturn(username, sessionKey, sessionID, Directory.ToSecureData());

                return (aesKey, connReturnVals);


            }

            public async Task<bool> ValidateSession(ConnectedSessionReturn connSession, SecureData decryptKey)
            {
                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());
                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                try
                {
                    ActiveSession? sess = null;

                    foreach (var item in ActiveSessList)
                    {
                        if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                        {
                            sess = item;
                            break;
                        }
                    }

                    if (sess == null)
                    {
                        throw new Exception("A session with this ID and user does not exist.");
                    }

                    DateTime parsedTimeCheck = DateTime.Parse(sess.Expiry, null, System.Globalization.DateTimeStyles.AssumeUniversal);

                    if (DateTime.UtcNow > parsedTimeCheck)
                    {
                        // Session expired, remove it
                        ActiveSessList.Remove(sess);
                        var updatedJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                        await JSONDataHandler.SaveJson(updatedJson);

                        return false;
                    }
                    else
                    {
                        // Validate IsTrusted field and Session Key
                        var isTrustedDecrypted = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(sess.IsTrusted), SecuritySettings.PublicKey); //Function will auto stop if bad
                        var parts = isTrustedDecrypted.ConvertToString().Split('|');

                        var isKeyGood = SimpleAESEncryption.Decrypt(SimpleAESEncryption.AESEncryptedText.FromUTF8String(sess.SessionKey), decryptKey); //Function will auto stop if bad


                        if (isKeyGood.ConvertToString() != connSession.SessionKey.ConvertToString())
                        {
                            // Tampering detected
                            ActiveSessList.Remove(sess);
                            var updatedCancelJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                            await JSONDataHandler.SaveJson(updatedCancelJson);

                            throw new Exception("The data for this session does not match and the token has been invalidated.");
                        }

                        if (parts.Length != 2)
                        {
                            throw new Exception("Invalid session trusted data format.");
                        }

                        var expiryString = parts[0];
                        bool isTrusted = bool.Parse(parts[1]);

                        if (expiryString != sess.Expiry)
                        {
                            // Tampering detected
                            ActiveSessList.Remove(sess);
                            var updatedCancelJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                            await JSONDataHandler.SaveJson(updatedCancelJson);

                            throw new Exception("The data for this session does not match and the token has been invalidated.");
                        }

                        // Extend session
                        DateTime newExpiry = DateTime.UtcNow.AddMinutes(isTrusted ? SecuritySettings.TrustedExpiryDuration : SecuritySettings.ExpiryDuration);
                        var newIsTrustedData = newExpiry.ToString("o") + "|" + isTrusted.ToString();
                        var newEncIsTrusted = SimpleAESEncryption.Encrypt(newIsTrustedData, SecuritySettings.PublicKey).ToString();

                        // Replace old session
                        ActiveSessList.Remove(sess);
                        ActiveSessList.Add(new ActiveSession(sess.Username, sess.SessionID, sess.SessionKey, newExpiry.ToString("o"), newEncIsTrusted, sess.ChecksAndLastTry));

                        var updatedSessionJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                        await JSONDataHandler.SaveJson(updatedSessionJson);

                        return true;
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Session validation error: {ex.Message}", ex);
                }
            }

            public async Task LogoutUser(ConnectedSessionReturn connSession, SecureData decryptKey)
            {

                await ValidateSession(connSession, decryptKey); //You don't really need to verify the bool, it should throw an exception automatically

                var loadedJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJSON, "Sessions", SecuritySettings.PublicKey);

                try
                {
                    ActiveSession? sess = null;

                    foreach (var item in ActiveSessList)
                    {
                        if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                        {
                            sess = item;
                        }
                    }

                    ActiveSessList.Remove(sess);
                    var updatedJson = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);
                    await JSONDataHandler.SaveJson(updatedJson);
                }

                catch (Exception ex)
                {
                    throw new Exception($"An Error Has Occured: {ex}");
                }


            }
            //Remember to wipe the connSession and decryptKey

            public async Task RemoveAccount(ConnectedSessionReturn connSession, SecureData decryptKey)
            {


                await ValidateSession(connSession, decryptKey); //You don't really need to verify the bool, it should throw an exception automatically

                await LogoutUser(connSession, decryptKey);

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                var matchedUser = UserList.FirstOrDefault(user => user.Username == connSession.Username.ConvertToString());


                if (matchedUser == null)
                {
                    throw new Exception("This user does not exist.");
                }


                UserList.Remove(matchedUser);

                var updatedJson = await JSONDataHandler.UpdateJson<List<AccountData>>(loadedJson, "AccountsList", UserList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedJson);


            }


            public async Task ResetPassword(ConnectedSessionReturn connSession, SecureData decryptKey, SecureData NewPassword, SecureData RecoveryPass)
            {

                await ValidateSession(connSession, decryptKey);

                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);
                var ActiveSessList = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedJson, "Sessions", SecuritySettings.PublicKey);


                AccountData? matchedUser = null;

                foreach (var user in UserList)
                {


                    if (user.Username == connSession.Username.ConvertToString())
                    {
                        matchedUser = user;
                        break; // Exit loop once a match is found
                    }
                }

                if (matchedUser == null)
                {
                    throw new Exception("This user does not exist.");
                }

                ActiveSession? matchedSess = null;

                foreach (var session in ActiveSessList)
                {

                    if (session.Username == connSession.Username.ConvertToString())
                    {
                        matchedSess = session;
                        break; // Exit loop once a match is found
                    }
                }

                if (matchedUser == null)
                {
                    throw new Exception("This session does not exist.");
                }

                var decryptedMatchedSessCALT = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(matchedSess.ChecksAndLastTry), SecuritySettings.PublicKey).ConvertToString();

                var decryptedRecoveryKey = SimpleAESEncryption.Decrypt(AESEncryptedText.FromUTF8String(matchedUser.RecoveryDataKey), decryptKey).ConvertToString();

                var parts = decryptedMatchedSessCALT.Split('|');
                int number = int.Parse(parts[0]);
                DateTime time = DateTime.Parse(parts[1], null, System.Globalization.DateTimeStyles.RoundtripKind);

                //Decrypt all things in matchedUser
                if (decryptedRecoveryKey != RecoveryPass.ConvertToString() && !(number == SecuritySettings.FailRecoveryCheck || number == -1))
                {
                    if (number == -1 && time < DateTime.UtcNow)
                    {
                        var newUpdatedVal = ((0) + "|" + time.ToString("o"));
                        matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                        await JSONDataHandler.SaveJson(loadedJson);
                        throw new Exception("The recovery key is invalid, please try again.");

                    }

                    else if (number == -1 && time > DateTime.UtcNow)
                    {
                        var newUpdatedVal2 = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.Local);
                        throw new Exception($"The recovery key was invalid too many times, please try again at {newUpdatedVal2.ToString("yyyy-MM-dd HH:mm:ss")}");
                    }

                    else
                    {
                        var newUpdatedVal = ((number + 1) + "|" + time.ToString("o"));
                        matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                        await JSONDataHandler.SaveJson(loadedJson);
                        throw new Exception("The recovery key is invalid, please try again.");

                    }

                }

                else if (decryptedRecoveryKey != RecoveryPass.ConvertToString() && (number == SecuritySettings.FailRecoveryCheck - 1))
                {
                    time.AddMinutes(SecuritySettings.TimeToNextRecovery);
                    var newUpdatedVal = ((-1) + "|" + time.ToString("o"));
                    DateTime localTime = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, TimeZoneInfo.Local);
                    matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();

                    await JSONDataHandler.SaveJson(loadedJson);
                    throw new Exception($"The recovery key was invalid too many times, please try again at {localTime.ToString("yyyy-MM-dd HH:mm:ss")}");
                }

                else if (matchedUser.RecoveryDataKey == RecoveryPass.ConvertToString())
                {
                    var newUpdatedVal = ((0) + "|" + time.ToString("o"));
                    matchedSess.ChecksAndLastTry = SimpleAESEncryption.Encrypt(newUpdatedVal, SecuritySettings.PublicKey).ToString();
                    await JSONDataHandler.SaveJson(loadedJson);
                    //The key is right!
                }

                matchedUser.Password = await PasswordHandler.GeneratePasswordHashAsync(NewPassword);

                SecureData encryptionkey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData();

                var recoverykey = PasswordGenerator.GeneratePassword(256, true, true, true, true).ToSecureData(); //Return this

                matchedUser.RecoveryDataKey = SimpleAESEncryption.Encrypt(recoverykey.ConvertToString(), encryptionkey).ToString();

                var encryptedkey = SimpleAESEncryption.Encrypt(encryptionkey.ConvertToString(), NewPassword).ToString();

                var checkData = 0.ToString() + "|" + DateTime.UtcNow.ToString("o");

                var encCheckData = SimpleAESEncryption.Encrypt(checkData, SecuritySettings.PublicKey).ToString();

                await JSONDataHandler.SaveJson(loadedJson);

                //Now to update the sessions (We remove them)

                var loadedActiveSessionsJSON = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var UserRelatedSessions = (List<ActiveSession>)await JSONDataHandler.GetVariable<List<ActiveSession>>(loadedActiveSessionsJSON, "Sessions", SecuritySettings.PublicKey);

                List<ActiveSession> sessions = new List<ActiveSession>();

                foreach (var item in UserRelatedSessions)
                {
                    if (item.Username == connSession.Username.ConvertToString() && item.SessionID == connSession.SessionID.ConvertToString())
                    {
                        sessions.Remove(item);
                    }
                }


                var updatedSessList = await JSONDataHandler.UpdateJson<List<ActiveSession>>(loadedActiveSessionsJSON, "Sessions", ActiveSessList, SecuritySettings.PublicKey);

                await JSONDataHandler.SaveJson(updatedSessList);


            }

            public async Task<List<string>> GetAllUsernames(ConnectedSessionReturn connSession, SecureData decryptKey)
            {
                var loadedJson = await JSONDataHandler.LoadJsonFile("Users", connSession.Directory.ConvertToString());

                var names = new List<string>();

                List<AccountData> UserList = (List<AccountData>)await JSONDataHandler.GetVariable<List<AccountData>>(loadedJson, "AccountsList", SecuritySettings.PublicKey);

                foreach (var item in UserList)
                {
                    names.Add(item.Username);
                }

                return names;


            }



        }


    }

    //Unused for a 
    public static class Utilities
    {
        public static string CreateUUID()
        {
            var uuidBuilder = new StringBuilder();

            // Generates 20 random values and concatenates them into the UUID
            for (int i = 0; i < 20; i++)
            {
                var newval = RNGCSP.RollDice(9).ToString();
                uuidBuilder.Append(newval);
            }

            return uuidBuilder.ToString();
        }

        internal static string GetRandomLengthString()
        {
            var valBuilder = new StringBuilder();

            // Random number of turns between 1 and 20
            int turns = RNGCSP.RollDice(20);

            // Generates a random number of random values and concatenates them
            for (int i = 0; i < turns; i++)
            {
                var newval = RNGCSP.RollDice(9).ToString();
                valBuilder.Append(newval);
            }

            return valBuilder.ToString();
        }



    }




    //RNGCSP Class Copied from https://gist.github.com/sachintha81/a4613d09de6b5f9d6a1a99dbf46e2385
    class RNGCSP
    {
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

        // This method simulates a roll of the dice. The input parameter is the
        // number of sides of the dice.

        public static byte RollDice(byte numberSides)
        {
            if (numberSides <= 0)
                throw new ArgumentOutOfRangeException("numberSides");

            // Create a byte array to hold the random value.
            byte[] randomNumber = new byte[1];
            do
            {
                // Fill the array with a random value.
                rngCsp.GetBytes(randomNumber);
            }
            while (!IsFairRoll(randomNumber[0], numberSides));
            // Return the random number mod the number
            // of sides.  The possible values are zero-
            // based, so we add one.
            return (byte)((randomNumber[0] % numberSides) + 1);
        }

        private static bool IsFairRoll(byte roll, byte numSides)
        {
            // There are MaxValue / numSides full sets of numbers that can come up
            // in a single byte.  For instance, if we have a 6 sided die, there are
            // 42 full sets of 1-6 that come up.  The 43rd set is incomplete.
            int fullSetsOfValues = Byte.MaxValue / numSides;

            // If the roll is within this range of fair values, then we let it continue.
            // In the 6 sided die case, a roll between 0 and 251 is allowed.  (We use
            // < rather than <= since the = portion allows through an extra 0 value).
            // 252 through 255 would provide an extra 0, 1, 2, 3 so they are not fair
            // to use.
            return roll < numSides * fullSetsOfValues;
        }
    }

}
