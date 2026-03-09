using System.Text;
using System;
using System.Runtime.InteropServices;

namespace WISecureData
{
    public static class SecureDataExtensions
    {
        // Convert a string to SecureData, securely clearing the original string in memory
        public static SecureData ToSecureData(this string value)
        {
            try
            {
                if (value == null)
                    throw new ArgumentNullException(nameof(value));

                byte[] bytes = Encoding.UTF8.GetBytes(value);

                // Securely clear the original string in memory
                value.SecureClear();
                return new SecureData(bytes);
            }

            catch
            {
                throw new Exception("Failed to Convert to SecureData.");
            }
        }

        // Securely clear the contents of a string by overwriting with null characters
        public static void SecureClear(this string value)
        {
            if (string.IsNullOrEmpty(value)) return;

            // Prevent clearing interned or literal strings
            if (string.IsInterned(value) != null)
            {
                // Log a warning or silently skip clearing
                Console.WriteLine("Warning: Attempted to clear an interned or literal string. Skipping.");
                return;
            }

            var span = MemoryMarshal.AsMemory(value.AsMemory()).Span;
            span.Fill('\0');
        }

    }
}
