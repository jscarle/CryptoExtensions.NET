using System.IO;

namespace System.Security.Cryptography
{
    public static class Extensions
    {
        private const int SALT_SIZE = 32; // 256 bits
        private const int HASH_SIZE = 32; // 256 bits
        private const int KEY_SIZE = 32;  // 256 bits
        private const int IV_SIZE = 16;   // 128 bits
        private const int ITERATIONS = 64000;
        private static readonly HashAlgorithmName ALGORITHM = HashAlgorithmName.SHA256;

        public static string Hash(this string password)
        {
            byte[] salt = new byte[SALT_SIZE];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            byte[] hash;
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, ALGORITHM))
                hash = pbkdf2.GetBytes(HASH_SIZE);

            byte[] saltedHash = new byte[salt.Length + hash.Length];
            Buffer.BlockCopy(salt, 0, saltedHash, 0, salt.Length);
            Buffer.BlockCopy(hash, 0, saltedHash, salt.Length, hash.Length);

            return Convert.ToBase64String(saltedHash);
        }

        public static bool CompareToHash(this string password, string hash)
        {
            try
            {
                byte[] saltedHash = Convert.FromBase64String(hash);

                byte[] salt = new byte[SALT_SIZE];
                Buffer.BlockCopy(saltedHash, 0, salt, 0, salt.Length);

                byte[] goodHash = new byte[(saltedHash.Length - salt.Length)];
                Buffer.BlockCopy(saltedHash, salt.Length, goodHash, 0, goodHash.Length);

                byte[] testHash;
                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, ALGORITHM))
                    testHash = pbkdf2.GetBytes(HASH_SIZE);

                uint diff = (uint)goodHash.Length ^ (uint)testHash.Length;
                for (int i = 0; i < goodHash.Length && i < testHash.Length; i++)
                {
                    diff |= (uint)(goodHash[i] ^ testHash[i]);
                }
                return diff == 0;
            }
            catch (Exception ex)
            {
                if (ex is FormatException || ex is ArgumentException)
                {
                    return false;
                }

                throw;
            }
        }

        public static string Encrypt(this string text, string password)
        {
            byte[] salt = new byte[SALT_SIZE];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            byte[] key;
            byte[] iv;
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, ALGORITHM))
            {
                key = pbkdf2.GetBytes(KEY_SIZE);
                iv = pbkdf2.GetBytes(IV_SIZE);
            }

            byte[] encrypted;
            using (Aes aes = Aes.Create())
            using (ICryptoTransform encryptor = aes.CreateEncryptor(key, iv))
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    streamWriter.Write(text);
                encrypted = memoryStream.ToArray();
            }

            byte[] saltedEncrypted = new byte[salt.Length + encrypted.Length];
            Buffer.BlockCopy(salt, 0, saltedEncrypted, 0, salt.Length);
            Buffer.BlockCopy(encrypted, 0, saltedEncrypted, salt.Length, encrypted.Length);

            return Convert.ToBase64String(saltedEncrypted);
        }

        public static string Decrypt(this string text, string password)
        {
            try
            {
                byte[] saltedEncrypted = Convert.FromBase64String(text);

                byte[] salt = new byte[SALT_SIZE];
                Buffer.BlockCopy(saltedEncrypted, 0, salt, 0, salt.Length);

                byte[] encrypted = new byte[(saltedEncrypted.Length - salt.Length)];
                Buffer.BlockCopy(saltedEncrypted, salt.Length, encrypted, 0, encrypted.Length);

                byte[] key;
                byte[] iv;
                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, ALGORITHM))
                {
                    key = pbkdf2.GetBytes(KEY_SIZE);
                    iv = pbkdf2.GetBytes(IV_SIZE);
                }

                using (Aes aes = Aes.Create())
                using (ICryptoTransform decryptor = aes.CreateDecryptor(key, iv))
                using (MemoryStream memoryStream = new MemoryStream(encrypted))
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (StreamReader streamReader = new StreamReader(cryptoStream))
                    return streamReader.ReadToEnd();
            }
            catch (Exception ex)
            {
                if (ex is FormatException || ex is ArgumentException || ex is CryptographicException)
                {
                    return "";
                }

                throw;
            }
        }
    }
}
