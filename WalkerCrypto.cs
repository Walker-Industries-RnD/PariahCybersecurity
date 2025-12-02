using Konscious.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using WISecureData;

namespace Walker.Crypto
{
    public static class SimpleAESEncryption
    {
        public struct AESEncryptedText
        {
            public string Salt;         // Base64
            public string IV;           // Base64
            public string EncryptedText; // Base64 (ciphertext + tag)

            public override string ToString() => $"{Salt}|{IV}|{EncryptedText}";

            public static AESEncryptedText FromString(string input)
            {
                var parts = input.Split('|');
                if (parts.Length != 3)
                    throw new FormatException("Invalid encrypted format. Expected: Salt|IV|Ciphertext");
                return new AESEncryptedText
                {
                    Salt = parts[0],
                    IV = parts[1],
                    EncryptedText = parts[2]
                };
            }
        }

        private static byte[] DeriveKey(SecureData password, byte[] salt, int keyBytes = 32)
        {
            var argon2 = new Argon2id(password.ConvertToBytes())
            {
                Salt = salt,
                DegreeOfParallelism = 2,
                MemorySize = 19456,  // ~19 MiB – OWASP 2025 minimum
                Iterations = 10 //LOL good luck breaking this
            };
            return argon2.GetBytes(keyBytes);
        }

        public static AESEncryptedText Encrypt(string plainText, SecureData password)
        {
            if (plainText == null) throw new ArgumentNullException(nameof(plainText));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var salt = RandomNumberGenerator.GetBytes(16);
            var iv = RandomNumberGenerator.GetBytes(12);
            var key = DeriveKey(password, salt);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(true, new AeadParameters(new KeyParameter(key), 128, iv));

            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var output = new byte[cipher.GetOutputSize(plainBytes.Length)];
            var len = cipher.ProcessBytes(plainBytes, 0, plainBytes.Length, output, 0);
            len += cipher.DoFinal(output, len);
            Array.Resize(ref output, len);

            return new AESEncryptedText
            {
                Salt = Convert.ToBase64String(salt),
                IV = Convert.ToBase64String(iv),
                EncryptedText = Convert.ToBase64String(output)
            };
        }

        public static string Decrypt(string encryptedText, string ivBase64, string saltBase64, SecureData password)
        {
            if (encryptedText == null) throw new ArgumentNullException(nameof(encryptedText));
            if (ivBase64 == null) throw new ArgumentNullException(nameof(ivBase64));
            if (saltBase64 == null) throw new ArgumentNullException(nameof(saltBase64));
            if (password == null) throw new ArgumentNullException(nameof(password));

            var salt = Convert.FromBase64String(saltBase64);
            var iv = Convert.FromBase64String(ivBase64);
            var key = DeriveKey(password, salt);

            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

            var input = Convert.FromBase64String(encryptedText);
            var output = new byte[cipher.GetOutputSize(input.Length)];
            var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);

            return Encoding.UTF8.GetString(output, 0, len);
        }

        public static SecureData Decrypt(AESEncryptedText encrypted, SecureData password)
        {
            var plain = Decrypt(encrypted.EncryptedText, encrypted.IV, encrypted.Salt, password);
            return SecureData.FromString(plain);
        }
    }

    public static class AsyncAESEncryption
    {
        public static Task<SimpleAESEncryption.AESEncryptedText> EncryptAsync(
            string plainText, SecureData password, Action<double>? progress = null)
            => Task.Run(() =>
            {
                var result = SimpleAESEncryption.Encrypt(plainText, password);
                progress?.Invoke(1.0);
                return result;
            });

        public static Task<string> DecryptAsync(
            SimpleAESEncryption.AESEncryptedText enc, SecureData password, Action<double>? progress = null)
            => Task.Run(() =>
            {
                progress?.Invoke(0.5);
                var result = SimpleAESEncryption.Decrypt(enc, password);
                progress?.Invoke(1.0);
                return result.ConvertToString();
            });

        public static Task<byte[]> DecryptBytesAsync(
            SimpleAESEncryption.AESEncryptedText enc, SecureData password, Action<double>? progress = null)
            => Task.Run(() =>
            {
                var str = SimpleAESEncryption.Decrypt(enc, password);
                progress?.Invoke(1.0);
                return Convert.FromBase64String(str.ConvertToString());
            });

        public static Task<SimpleAESEncryption.AESEncryptedText> EncryptBytesAsync(
            byte[] data, SecureData password, Action<double>? progress = null)
            => Task.Run(() =>
            {
                var str = Convert.ToBase64String(data);
                var result = SimpleAESEncryption.Encrypt(str, password);
                progress?.Invoke(1.0);
                return result;
            });
    }

    public static class AESFileEncryptor
    {
        private const int ChunkSize = 4 * 1024 * 1024; // 4 MiB

        public static async Task EncryptFileAsync(
            string inputPath, string outputPath, SecureData password, Action<double>? progress = null)
        {
            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            await using var writer = new StreamWriter(outputPath);

            var total = input.Length;
            var processed = 0L;
            var buffer = new byte[ChunkSize];

            int read;
            while ((read = await input.ReadAsync(buffer)) > 0)
            {
                var chunk = new byte[read];
                Buffer.BlockCopy(buffer, 0, chunk, 0, read);

                var encrypted = await AsyncAESEncryption.EncryptBytesAsync(chunk, password);
                await writer.WriteLineAsync(encrypted.ToString());

                processed += read;
                progress?.Invoke((double)processed / total);
            }
        }

        public static async Task DecryptFileAsync(
            string inputPath, string outputPath, SecureData password, Action<double>? progress = null)
        {
            using var reader = new StreamReader(inputPath);
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

            var lines = new List<string>();
            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
                lines.Add(line);

            var total = lines.Count;
            if (total == 0)
            {
                progress?.Invoke(1.0);
                return;
            }

            for (int i = 0; i < total; i++)
            {
                var enc = SimpleAESEncryption.AESEncryptedText.FromString(lines[i]);
                var bytes = await AsyncAESEncryption.DecryptBytesAsync(enc, password);
                await output.WriteAsync(bytes);

                progress?.Invoke((i + 1.0) / total);
            }

        }
    }
}