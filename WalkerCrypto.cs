using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Walker.Crypto
{
    public static class SimpleAESEncryption
    {
        public struct AESEncryptedText
        {
            public string IV;
            public string EncryptedText;

            public override string ToString() => $"{IV}|{EncryptedText}";

            public static AESEncryptedText FromUTF8String(string input)
            {
                var parts = input.Split('|');
                if (parts.Length != 2) throw new FormatException("Invalid AESEncryptedText format.");
                return new AESEncryptedText { IV = parts[0], EncryptedText = parts[1] };
            }
        }

        public static byte[] GenerateRandomBytes(int size)
        {
            var rnd = new SecureRandom();
            var bytes = new byte[size];
            rnd.NextBytes(bytes);
            return bytes;
        }

        // Derive a 256-bit key by hashing the SecureString with SHA-256
        public static byte[] DeriveKey(SecureString password, int keyBytes)
        {
            IntPtr ptr = Marshal.SecureStringToGlobalAllocUnicode(password);
            try
            {
                string pwd = Marshal.PtrToStringUni(ptr);
                using var sha = SHA256.Create();
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(pwd));
                if (hash.Length == keyBytes) return hash;
                var key = new byte[keyBytes];
                Array.Copy(hash, key, Math.Min(hash.Length, keyBytes));
                return key;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptr);
            }
        }

        public static AESEncryptedText Encrypt(string plainText, SecureString password)
        {
            var aes = new GcmBlockCipher(new AesEngine());
            byte[] iv = GenerateRandomBytes(12);
            byte[] key = DeriveKey(password, 32);
            aes.Init(true, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherBuf = new byte[aes.GetOutputSize(plainBytes.Length)];

            int off = aes.ProcessBytes(plainBytes, 0, plainBytes.Length, cipherBuf, 0);
            off += aes.DoFinal(cipherBuf, off);
            Array.Resize(ref cipherBuf, off);

            return new AESEncryptedText
            {
                IV = Convert.ToBase64String(iv),
                EncryptedText = Convert.ToBase64String(cipherBuf)
            };
        }

        public static SecureString Decrypt(AESEncryptedText encrypted, SecureString password)
        {
            string plain = Decrypt(encrypted.EncryptedText, encrypted.IV, password);
            var ss = new SecureString();
            foreach (char c in plain) ss.AppendChar(c);
            ss.MakeReadOnly();
            return ss;
        }

        public static string Decrypt(string encryptedText, string ivBase64, SecureString password)
        {
            var aes = new GcmBlockCipher(new AesEngine());
            byte[] iv = Convert.FromBase64String(ivBase64);
            byte[] key = DeriveKey(password, 32);
            aes.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

            byte[] cipher = Convert.FromBase64String(encryptedText);
            byte[] plainBuf = new byte[aes.GetOutputSize(cipher.Length)];

            int off = aes.ProcessBytes(cipher, 0, cipher.Length, plainBuf, 0);
            off += aes.DoFinal(plainBuf, off);

            return Encoding.UTF8.GetString(plainBuf, 0, off);
        }
    }

    public static class AsyncAESEncryption
    {
        public static async Task<SimpleAESEncryption.AESEncryptedText> EncryptAsync(string plainText, SecureString password, Action<double> progress = null)
        {
            return await Task.Run(() =>
            {
                var aes = new GcmBlockCipher(new AesEngine());
                byte[] iv = SimpleAESEncryption.GenerateRandomBytes(12);
                byte[] key = SimpleAESEncryption.DeriveKey(password, 32);
                aes.Init(true, new AeadParameters(new KeyParameter(key), 128, iv));

                byte[] data = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherBuf = new byte[aes.GetOutputSize(data.Length)];

                int pos = 0;
                int chunkSize = 1024;
                for (int i = 0; i < data.Length; i += chunkSize)
                {
                    int len = aes.ProcessBytes(data, i, Math.Min(chunkSize, data.Length - i), cipherBuf, pos);
                    pos += len;
                    progress?.Invoke((double)pos / data.Length);
                }
                pos += aes.DoFinal(cipherBuf, pos);
                Array.Resize(ref cipherBuf, pos);

                return new SimpleAESEncryption.AESEncryptedText
                {
                    IV = Convert.ToBase64String(iv),
                    EncryptedText = Convert.ToBase64String(cipherBuf)
                };
            });
        }

        public static Task<string> DecryptAsync(SimpleAESEncryption.AESEncryptedText enc, SecureString pwd, Action<double> progress = null)
            => DecryptAsync(enc.EncryptedText, enc.IV, pwd, progress);

        public static async Task<string> DecryptAsync(string encryptedText, string ivBase64, SecureString password, Action<double> progress = null)
        {
            return await Task.Run(() =>
            {
                var aes = new GcmBlockCipher(new AesEngine());
                byte[] iv = Convert.FromBase64String(ivBase64);
                byte[] key = SimpleAESEncryption.DeriveKey(password, 32);
                aes.Init(false, new AeadParameters(new KeyParameter(key), 128, iv));

                byte[] cipher = Convert.FromBase64String(encryptedText);
                byte[] plainBuf = new byte[aes.GetOutputSize(cipher.Length)];

                int pos = 0;
                int chunkSize = 1024;
                for (int i = 0; i < cipher.Length; i += chunkSize)
                {
                    int len = aes.ProcessBytes(cipher, i, Math.Min(chunkSize, cipher.Length - i), plainBuf, pos);
                    pos += len;
                    progress?.Invoke((double)pos / cipher.Length);
                }
                pos += aes.DoFinal(plainBuf, pos);

                return Encoding.UTF8.GetString(plainBuf, 0, pos);
            });
        }

        public static async Task<SimpleAESEncryption.AESEncryptedText> EncryptBytesAsync(byte[] data, SecureString password, Action<double> progress = null)
        {
            // Convert chunk to Base64 string
            string chunkStr = Convert.ToBase64String(data);
            return await EncryptAsync(chunkStr, password, progress);
        }

        public static async Task<byte[]> DecryptBytesAsync(SimpleAESEncryption.AESEncryptedText enc, SecureString password, Action<double> progress = null)
        {
            string base64 = await DecryptAsync(enc, password, progress);
            return Convert.FromBase64String(base64);
        }
    }

    public static class AESFileEncryptor
    {
        private const int ChunkSize = 4 * 1024 * 1024; // 4MiB per chunk

   
        public static async Task EncryptFileAsync(string inputPath, string outputPath, SecureString password, Action<double> progress = null)
        {
            using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read);
            using var writer = new StreamWriter(outputPath, false, Encoding.UTF8);

            long total = input.Length;
            long readSoFar = 0;
            byte[] buffer = new byte[ChunkSize];
            int read;
            while ((read = await input.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                // Copy exact bytes
                var chunk = new byte[read];
                Array.Copy(buffer, 0, chunk, 0, read);

                // Encrypt chunk
                var encChunk = await AsyncAESEncryption.EncryptBytesAsync(chunk, password, p => progress?.Invoke((readSoFar + p * read) / total));

                // Write as "IV|EncryptedBase64"
                await writer.WriteLineAsync(encChunk.ToString());

                readSoFar += read;
                progress?.Invoke((double)readSoFar / total);
            }
            await writer.FlushAsync();
        }

        public static async Task DecryptFileAsync(string inputPath, string outputPath, SecureString password, Action<double> progress = null)
        {
            using var reader = new StreamReader(inputPath, Encoding.UTF8);
            using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write);

            // First, read all lines to count chunks
            var lines = new List<string>();
            string line;
            while ((line = await reader.ReadLineAsync()) != null)
                lines.Add(line);

            int chunkCount = lines.Count;
            for (int i = 0; i < chunkCount; i++)
            {
                var encChunk = SimpleAESEncryption.AESEncryptedText.FromUTF8String(lines[i]);
                var bytes = await AsyncAESEncryption.DecryptBytesAsync(encChunk, password, p => progress?.Invoke((i + p) / (double)chunkCount));
                await output.WriteAsync(bytes, 0, bytes.Length);
            }
            progress?.Invoke(1.0);
        }
    }

}
