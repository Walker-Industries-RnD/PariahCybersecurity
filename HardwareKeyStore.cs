using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace WISecureData
{
    // A root-key store that binds a key to hardware where the platform allows it, so
    // the key itself cannot be exfiltrated (even by an admin) - it never leaves the
    // secure hardware. You use it to Wrap (encrypt) and Unwrap (decrypt) a small
    // symmetric key; the private operation happens inside the hardware.
    //
    // Backends:
    //   - Windows -> TPM 2.0 via CNG (Microsoft Platform Crypto Provider). Non-exportable.
    //               Falls back to the software KSP when no usable TPM is present.
    //   - macOS   -> intended: Secure Enclave via Keychain (SecKey, kSecAttrTokenIDSecureEnclave).
    //               Not implemented yet; currently uses the software fallback below.
    //   - Linux   -> intended: TPM 2.0 (tpm2-tss / PKCS#11), kernel keyring as fallback.
    //               Not implemented yet; currently uses the software fallback below.
    //
    // Honest limit: hardware backing protects the KEY from theft. When you Unwrap and
    // then use the key, the result is plaintext in normal process memory, where a
    // same-privilege attacker can still read it. This stops key exfiltration, not
    // moment-of-use reads.
    public interface IHardwareKeyStore : IDisposable
    {
        // True when the key is bound to real secure hardware (TPM / Secure Enclave).
        bool IsHardwareBacked { get; }

        // Human-readable description of the backend actually in use.
        string BackendName { get; }

        // Encrypts a small symmetric key (<= ~190 bytes for a 2048-bit key) with the
        // root key. The wrapped blob is safe to persist to disk.
        byte[] WrapKey(byte[] plaintextKey);

        // Decrypts a blob produced by WrapKey. On a hardware backend the private
        // operation happens inside the hardware and the root key never leaves it.
        byte[] UnwrapKey(byte[] wrappedKey);

        // Removes the persisted root key (for rotation / uninstall). No-op for the
        // in-memory software fallback.
        void DeletePersistedKey();
    }

    // Entry point: opens (or creates) the platform's root-key store.
    public static class HardwareKeyStore
    {
        public static IHardwareKeyStore Open(string keyName = "PariahRootKey")
        {
            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentException("Key name must be provided.", nameof(keyName));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return new WindowsHardwareKeyStore(keyName);

            // macOS / Linux backends are scaffolded (see interface notes). Until the
            // native Secure Enclave / TPM backends are wired up, the software fallback
            // keeps the API usable everywhere - it just reports IsHardwareBacked = false.
            return new SoftwareKeyStore(keyName);
        }
    }

    // Windows TPM-backed store via CNG. The RSA private key is created non-exportable
    // in the Microsoft Platform Crypto Provider (the TPM); if that provider or a TPM is
    // not available, it falls back to the Microsoft Software Key Storage Provider.
    [SupportedOSPlatform("windows")]
    internal sealed class WindowsHardwareKeyStore : IHardwareKeyStore
    {
        private const string PlatformProvider = "Microsoft Platform Crypto Provider"; // TPM
        private const string SoftwareProvider = "Microsoft Software Key Storage Provider";

        private readonly string _keyName;
        private readonly RSACng _rsa;

        public bool IsHardwareBacked { get; }
        public string BackendName { get; }

        public WindowsHardwareKeyStore(string keyName)
        {
            _keyName = keyName;

            try
            {
                _rsa = new RSACng(OpenOrCreate(keyName, PlatformProvider));
                IsHardwareBacked = true;
                BackendName = "Windows TPM (Microsoft Platform Crypto Provider)";
            }
            catch
            {
                // No usable TPM / provider - persist a non-exportable software key instead.
                _rsa = new RSACng(OpenOrCreate(keyName, SoftwareProvider));
                IsHardwareBacked = false;
                BackendName = "Windows software KSP (no usable TPM)";
            }
        }

        private static CngKey OpenOrCreate(string keyName, string provider)
        {
            var prov = new CngProvider(provider);

            if (CngKey.Exists(keyName, prov))
                return CngKey.Open(keyName, prov);

            var parameters = new CngKeyCreationParameters
            {
                Provider = prov,
                KeyUsage = CngKeyUsages.Decryption,
                ExportPolicy = CngExportPolicies.None, // non-exportable
                KeyCreationOptions = CngKeyCreationOptions.None,
            };
            parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

            return CngKey.Create(CngAlgorithm.Rsa, keyName, parameters);
        }

        public byte[] WrapKey(byte[] plaintextKey)
        {
            if (plaintextKey == null) throw new ArgumentNullException(nameof(plaintextKey));
            return _rsa.Encrypt(plaintextKey, RSAEncryptionPadding.OaepSHA256);
        }

        public byte[] UnwrapKey(byte[] wrappedKey)
        {
            if (wrappedKey == null) throw new ArgumentNullException(nameof(wrappedKey));
            return _rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        }

        public void DeletePersistedKey()
        {
            try
            {
                foreach (var provider in new[] { PlatformProvider, SoftwareProvider })
                {
                    var prov = new CngProvider(provider);
                    if (CngKey.Exists(_keyName, prov))
                    {
                        using var key = CngKey.Open(_keyName, prov);
                        key.Delete();
                    }
                }
            }
            catch { }
        }

        public void Dispose() => _rsa.Dispose();
    }

    // Portable software fallback so the API works on every OS. NOT hardware-backed and
    // process-local: the key exists only for this process's lifetime. Replace with the
    // Secure Enclave (macOS) / TPM (Linux) backend for real, persistent protection.
    internal sealed class SoftwareKeyStore : IHardwareKeyStore
    {
        private readonly RSA _rsa;

        public bool IsHardwareBacked => false;
        public string BackendName { get; }

        public SoftwareKeyStore(string keyName)
        {
            _rsa = RSA.Create(2048);
            BackendName = $"Software fallback (process-local, not hardware-backed) [{keyName}]";
        }

        public byte[] WrapKey(byte[] plaintextKey)
        {
            if (plaintextKey == null) throw new ArgumentNullException(nameof(plaintextKey));
            return _rsa.Encrypt(plaintextKey, RSAEncryptionPadding.OaepSHA256);
        }

        public byte[] UnwrapKey(byte[] wrappedKey)
        {
            if (wrappedKey == null) throw new ArgumentNullException(nameof(wrappedKey));
            return _rsa.Decrypt(wrappedKey, RSAEncryptionPadding.OaepSHA256);
        }

        public void DeletePersistedKey() { /* nothing persisted */ }

        public void Dispose() => _rsa.Dispose();
    }
}
