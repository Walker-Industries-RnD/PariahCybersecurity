using System.Text;

namespace WISecureData
{
    public static class SecureDataExtensions
    {
        // Convert a string to SecureData, securely clearing the original string in memory
        public static SecureData ToSecureData(this string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            byte[] bytes = Encoding.UTF8.GetBytes(value);

            // Securely clear the original string in memory
            value.SecureClear();
            return new SecureData(bytes);
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

            unsafe
            {
                fixed (char* chars = value)
                {
                    // Zero out original string content
                    for (int i = 0; i < value.Length; i++)
                        chars[i] = '\0';
                }
            }
        }

    }
}
