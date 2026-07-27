namespace WISecureData
{
    public static class SecureDataExtensions
    {
        // Convert a string to SecureData, securely clearing the original string in memory.
        public static SecureData ToSecureData(this string value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            // Reuse the single conversion path so the string-clearing behaviour
            // stays identical between the two entry points.
            return SecureData.FromString(value);
        }

        // Securely clear the contents of a string by overwriting it with null characters.
        //
        // NOTE: .NET strings are immutable and may be shared/interned, so this is a
        // best-effort scrub. It intentionally refuses to touch interned or literal
        // strings, because overwriting a pooled instance would corrupt every other
        // reference to it.
        public static void SecureClear(this string value)
        {
            if (string.IsNullOrEmpty(value)) return;

            // Prevent clearing interned or literal strings (would corrupt the intern pool).
            if (string.IsInterned(value) != null)
                return;

            unsafe
            {
                fixed (char* chars = value)
                {
                    // Zero out the original string content.
                    for (int i = 0; i < value.Length; i++)
                        chars[i] = '\0';
                }
            }
        }
    }
}
