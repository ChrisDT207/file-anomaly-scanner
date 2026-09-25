using System;
using System.Security.Cryptography;

namespace FileAnomalyScanner.Services
{
    public static class HashUtils
    {
        public static string ComputeSha256(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                // Empty string hash
                return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
            }

            using var sha256 = SHA256.Create();
            byte[] hashBytes = sha256.ComputeHash(data);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
    }
}
