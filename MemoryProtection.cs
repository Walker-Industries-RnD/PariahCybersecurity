using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace WISecureData
{
    // Per-OS memory-hardening primitives used by SecureData.
    //
    // The goal is to keep secret bytes from leaking through several channels:
    //   - the OS page file / swap (a locked page is never written to disk),
    //   - left-over copies in RAM (secure, non-elided zeroing on release), and
    //   - plain text sitting idle in the heap where a memory scanner can find it
    //     (the bytes are kept AES-256 encrypted at rest and only decrypted into a
    //     short-lived buffer for the moment they are actually used).
    //
    // The AES key lives in this process, so this defeats value-scanning tools and
    // casual snapshot dumps, but not a same-privilege attacker who dumps the whole
    // process and reconstructs the key. Page locking is best-effort and never throws.
    internal static class MemoryProtection
    {
        // Windows (kernel32)
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualLock(IntPtr address, UIntPtr size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool VirtualUnlock(IntPtr address, UIntPtr size);

        // Linux / macOS (libc). mlock/munlock return 0 on success, -1 on failure.
        [DllImport("libc", EntryPoint = "mlock", SetLastError = true)]
        private static extern int UnixMlock(IntPtr address, UIntPtr length);

        [DllImport("libc", EntryPoint = "munlock", SetLastError = true)]
        private static extern int UnixMunlock(IntPtr address, UIntPtr length);

        // True when the current OS exposes a page-locking primitive we know how to call.
        public static bool IsLockingSupported =>
            RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
            RuntimeInformation.IsOSPlatform(OSPlatform.OSX);

        // Attempts to lock the page(s) backing 'address' so the secret can never be
        // paged out to disk. The memory MUST already be pinned by the caller (a moving
        // address would make the lock meaningless). Returns true if it now needs unlock.
        public static bool TryLock(IntPtr address, int length)
        {
            if (address == IntPtr.Zero || length <= 0)
                return false;

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    return VirtualLock(address, (UIntPtr)(uint)length);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                    RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    return UnixMlock(address, (UIntPtr)(uint)length) == 0;
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }

            return false;
        }

        // Releases a lock previously taken by TryLock. Safe to call with the same
        // address/length even if the original lock silently failed.
        public static void Unlock(IntPtr address, int length)
        {
            if (address == IntPtr.Zero || length <= 0)
                return;

            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    VirtualUnlock(address, (UIntPtr)(uint)length);
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                         RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                    UnixMunlock(address, (UIntPtr)(uint)length);
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
        }

        // Overwrites the buffer with zeros using an implementation the JIT is
        // guaranteed not to optimize away (unlike Array.Clear on data proven dead).
        public static void SecureZero(byte[]? buffer)
        {
            if (buffer == null || buffer.Length == 0)
                return;

            CryptographicOperations.ZeroMemory(buffer);
        }

        // At-rest encryption.
        // A single random AES-256 key, generated once per process and held in a pinned
        // and page-locked buffer for the life of the process (the leaked GCHandle is
        // intentional; this is a process-wide singleton).
        private static readonly object _keyLock = new object();
        private static volatile byte[]? _processKey;

        private static byte[] ProcessKey
        {
            get
            {
                byte[]? key = _processKey;
                if (key != null)
                    return key;

                lock (_keyLock)
                {
                    if (_processKey == null)
                    {
                        var k = new byte[32]; // AES-256
                        RandomNumberGenerator.Fill(k);
                        try
                        {
                            var h = GCHandle.Alloc(k, GCHandleType.Pinned); // never freed by design
                            TryLock(h.AddrOfPinnedObject(), k.Length);
                        }
                        catch { }
                        _processKey = k;
                    }
                    return _processKey;
                }
            }
        }

        // Encrypts the plaintext for at-rest storage in RAM and returns a fresh
        // IV || ciphertext blob. The plaintext itself is left untouched (the caller
        // owns wiping it).
        public static byte[] Protect(byte[] plaintext)
        {
            if (plaintext == null || plaintext.Length == 0)
                return Array.Empty<byte>();

            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            using var aes = Aes.Create();
            aes.Key = ProcessKey;

            byte[] cipher = aes.EncryptCbc(plaintext, iv, PaddingMode.PKCS7);

            byte[] blob = new byte[iv.Length + cipher.Length];
            Buffer.BlockCopy(iv, 0, blob, 0, iv.Length);
            Buffer.BlockCopy(cipher, 0, blob, iv.Length, cipher.Length);

            CryptographicOperations.ZeroMemory(cipher);
            return blob;
        }

        // Reverses Protect, returning a freshly allocated plaintext buffer that the
        // caller is responsible for zeroing after use.
        public static byte[] Unprotect(byte[] blob)
        {
            if (blob == null || blob.Length <= 16)
                return Array.Empty<byte>();

            byte[] iv = new byte[16];
            Buffer.BlockCopy(blob, 0, iv, 0, 16);

            byte[] cipher = new byte[blob.Length - 16];
            Buffer.BlockCopy(blob, 16, cipher, 0, cipher.Length);

            using var aes = Aes.Create();
            aes.Key = ProcessKey;

            byte[] plaintext = aes.DecryptCbc(cipher, iv, PaddingMode.PKCS7);

            CryptographicOperations.ZeroMemory(cipher);
            return plaintext;
        }
    }
}
