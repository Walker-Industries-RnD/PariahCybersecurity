using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace WISecureData
{
    // A value type that holds sensitive bytes (keys, passwords, tokens) with hardened
    // memory handling:
    //   - the bytes are kept AES-256 encrypted at rest in RAM and are only decrypted
    //     into a short-lived buffer for the instant they are used, so a memory scanner
    //     (e.g. Cheat Engine) cannot find the secret by value;
    //   - the encrypted buffer is pinned and, where the OS allows, page-locked so it is
    //     never relocated by the GC nor written to the swap file; and
    //   - it is securely zeroed on Dispose (and, as a safety net, when the last copy is
    //     finalized) so secrets do not linger in RAM.
    //
    // The type stays a copy-by-value struct: copies share one backing buffer, exactly
    // as the previous implementation did, and the public API is unchanged.
    //
    // Note: this protects the data held by a SecureData. Values you pull out with
    // ConvertToString / ConvertToBytes are ordinary managed objects and are NOT
    // protected, so keep them short-lived. At-rest encryption also does not stop a
    // debugger/injector in the same process; see the wiki page for the full threat model.
    public readonly struct SecureData : IDisposable
    {
        private readonly SecureBuffer? _buffer;

        public SecureData(byte[] bytes)
        {
            if (bytes == null)
                throw new ArgumentNullException(nameof(bytes));

            _buffer = new SecureBuffer(bytes);
        }

        // Returns a FRESH plaintext copy of the secret (caller owns it), or throws a
        // clear error for an uninitialized (default) / disposed instance instead of a
        // bare NullReferenceException.
        private byte[] DecryptOrThrow()
        {
            byte[]? bytes = _buffer?.DecryptCopy();
            if (bytes == null)
                throw new InvalidOperationException("SecureData is uninitialized (default) or has been disposed.");
            return bytes;
        }

        // Convert SecureData to a byte array (a fresh, decrypted copy the caller owns)
        public byte[] ConvertToBytes()
        {
            try
            {
                return DecryptOrThrow();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Convert to Bytes.", ex);
            }
        }

        // Convert SecureData back to a string
        public string ConvertToString()
        {
            byte[]? plain = null;
            try
            {
                plain = DecryptOrThrow();
                return System.Text.Encoding.UTF8.GetString(plain);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Convert to String.", ex);
            }
            finally
            {
                // The decrypted copy only needs to live for the GetString call.
                MemoryProtection.SecureZero(plain);
            }
        }

        // Convert a string to SecureData and securely clear the original string in memory
        public static SecureData FromString(string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            try
            {
                byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);

                // Securely clear the original string in memory
                value.SecureClear();
                return new SecureData(bytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Convert to SecureData.", ex);
            }
        }

        // Override ToString for base64 representation of the byte array
        public override string ToString()
        {
            byte[]? plain = null;
            try
            {
                plain = DecryptOrThrow();
                return Convert.ToBase64String(plain);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Convert SecureData to String.", ex);
            }
            finally
            {
                MemoryProtection.SecureZero(plain);
            }
        }

        // Dispose to securely wipe (and unlock/unpin) the data in memory
        public void Dispose()
        {
            try
            {
                _buffer?.Dispose();
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Dispose SecureData.", ex);
            }
        }

        // Equality check with constant-time comparison to avoid timing attacks
        public static bool operator ==(SecureData left, SecureData right)
            => left.SecureCompare(right);

        public static bool operator !=(SecureData left, SecureData right)
            => !left.SecureCompare(right);

        public override bool Equals(object? obj)
            => obj is SecureData other && this == other;

        // Consistent with Equals (equal contents => equal length) while never hashing
        // the secret's contents into the value.
        public override int GetHashCode()
            => _buffer?.Length ?? 0;

        // Constant-time comparison of SecureData objects. Decrypts both operands into
        // short-lived buffers, compares without short-circuiting (FixedTimeEquals),
        // then wipes the plaintext copies.
        public bool SecureCompare(SecureData other)
        {
            byte[]? a = null, b = null;
            try
            {
                a = _buffer?.DecryptCopy() ?? Array.Empty<byte>();
                b = other._buffer?.DecryptCopy() ?? Array.Empty<byte>();
                return CryptographicOperations.FixedTimeEquals(a, b);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to Compare SecureData.", ex);
            }
            finally
            {
                MemoryProtection.SecureZero(a);
                MemoryProtection.SecureZero(b);
            }
        }

        // Owns the secret (AES-encrypted at rest) plus the OS resources protecting it
        // (a GC pin and, where supported, a page lock on the ciphertext). Cleanup is
        // idempotent and runs from either Dispose or the finalizer, whichever comes
        // first, so secrets are wiped even when a caller forgets to dispose. Because
        // every copy of the enclosing SecureData shares one instance, the finalizer
        // only runs once no copy remains reachable.
        private sealed class SecureBuffer : IDisposable
        {
            private readonly byte[] _protectedBytes; // IV || ciphertext (empty for a 0-length secret)
            private readonly int _plainLength;
            private GCHandle _handle;
            private readonly bool _locked;
            private int _disposed; // 0 = live, 1 = cleaned up (guarded via Interlocked)

            public SecureBuffer(byte[] plaintext)
            {
                _plainLength = plaintext.Length;

                if (plaintext.Length > 0)
                {
                    // Encrypt at rest, then wipe the incoming plaintext immediately so it
                    // does not linger in the heap.
                    _protectedBytes = MemoryProtection.Protect(plaintext);
                    MemoryProtection.SecureZero(plaintext);

                    try
                    {
                        // Pin the ciphertext so the GC cannot relocate it (leaving stale
                        // copies) and so the page lock targets a stable address.
                        _handle = GCHandle.Alloc(_protectedBytes, GCHandleType.Pinned);
                        _locked = MemoryProtection.TryLock(_handle.AddrOfPinnedObject(), _protectedBytes.Length);
                    }
                    catch
                    {
                        // Pinning/locking is a best-effort hardening step; never let it
                        // stop a SecureData from being created.
                    }
                }
                else
                {
                    _protectedBytes = Array.Empty<byte>();
                }
            }

            public int Length => Volatile.Read(ref _disposed) == 0 ? _plainLength : 0;

            // Returns a fresh, decrypted plaintext copy the caller must zero after use.
            // Returns null once the buffer has been wiped/released (or on a default instance).
            public byte[]? DecryptCopy()
            {
                if (Volatile.Read(ref _disposed) != 0)
                    return null;
                if (_plainLength == 0)
                    return Array.Empty<byte>();

                return MemoryProtection.Unprotect(_protectedBytes);
            }

            public void Dispose()
            {
                Cleanup();
                GC.SuppressFinalize(this);
            }

            ~SecureBuffer() => Cleanup();

            private void Cleanup()
            {
                // Ensure the wipe/unlock/unpin happens exactly once.
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                    return;

                try
                {
                    // Zero the ciphertext first, while it is still pinned at a known address.
                    MemoryProtection.SecureZero(_protectedBytes);

                    if (_handle.IsAllocated)
                    {
                        if (_locked)
                            MemoryProtection.Unlock(_handle.AddrOfPinnedObject(), _protectedBytes.Length);
                        _handle.Free();
                    }
                }
                catch
                {
                    // Cleanup runs from the finalizer too; it must never throw.
                }
            }
        }
    }
}
