namespace WISecureData
{
    public readonly struct SecureData : IDisposable
    {
        private readonly byte[] _bytes;

        public SecureData(byte[] bytes)
        {
            _bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
        }

        // Convert SecureData to a byte array
        public byte[] ConvertToBytes()
        {
            var copy = new byte[_bytes.Length];
            Buffer.BlockCopy(_bytes, 0, copy, 0, _bytes.Length);
            return copy;
        }

        // Convert SecureData back to a string
        public string ConvertToString()
        {
            return System.Text.Encoding.UTF8.GetString(_bytes);
        }

        // Convert a string to SecureData and securely clear the original string in memory
        public static SecureData FromString(string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(value);

            // Securely clear the original string in memory
            value.SecureClear();
            return new SecureData(bytes);
        }

        // Override ToString for base64 representation of the byte array
        public override string ToString()
        {
            return Convert.ToBase64String(_bytes);
        }

        // Dispose to clear data in memory
        public void Dispose()
        {
            if (_bytes != null)
                Array.Clear(_bytes, 0, _bytes.Length); // Wipe the data
        }

        // Equality check with constant-time comparison to avoid timing attacks
        public static bool operator ==(SecureData left, SecureData right)
            => left.SecureCompare(right);

        public static bool operator !=(SecureData left, SecureData right)
            => !left.SecureCompare(right);

        public override bool Equals(object? obj)
            => obj is SecureData other && this == other;

        public override int GetHashCode()
            => _bytes?.Length ?? 0;

        // Constant-time comparison of SecureData objects
        public bool SecureCompare(SecureData other)
        {
            if (other._bytes.Length != this._bytes.Length)
                return false;

            for (int i = 0; i < _bytes.Length; i++)
            {
                if (_bytes[i] != other._bytes[i])
                    return false;
            }

            return true;
        }
    }
}
