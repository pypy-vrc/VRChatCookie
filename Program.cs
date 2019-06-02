using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace VRChatCookie
{
    public static class Program
    {
        private static readonly RegistryKey m_Reg = Registry.CurrentUser.CreateSubKey(@"Software\VRChat\vrchat");

        private static string GetKey(string name)
        {
            var stringBuilder = new StringBuilder();
            var bytes = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(name));
            for (int i = 0; i < bytes.Length; ++i)
            {
                stringBuilder.Append(bytes[i].ToString("X2"));
            }
            // djb2-xor
            var hash = 5381U;
            foreach (var c in stringBuilder.ToString())
            {
                hash = hash * 33 ^ c;
            }
            stringBuilder.Append("_h");
            stringBuilder.Append(hash);
            return stringBuilder.ToString();
        }

        public static void Set(string key, string value)
        {
            m_Reg.SetValue(GetKey(key), DESEncryption.Encrypt(value));
        }

        public static string Get(string key)
        {
            if (m_Reg.GetValue(GetKey(key)) is byte[] bytes &&
                DESEncryption.TryDecrypt(bytes, out string value))
            {
                return value;
            }
            return string.Empty;
        }

        public static void Main(string[] args)
        {
            // EditThisCookie : https://chrome.google.com/webstore/detail/fngmhnnpilhplaeedifhccceomclgfbg
            // User-Agent Switcher : https://chrome.google.com/webstore/detail/lkmofgnohbedopheiphabfhfjgkhfcgf
            // User-Agent: VRC.Core.BestHTTP

            // Set Secure Perfs
            Set("username", string.Empty);
            Set("password", string.Empty);
            Set("authTokenProvider", "vrchat");
            Set("authTokenProviderUserId", "zetyx");
            Set("authToken", "authcookie_5265751f-8d83-4f58-8ff7-6a631a64ad68");
            Set("humanName", "pypy");

            //
            // Bake Some Cookies
            //
            var Date = DateTime.Now;
            var LastAccess = DateTime.UtcNow;
            var Expires = DateTime.UtcNow.AddDays(5);
            using (var file = File.Open(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) + @"Low\VRChat\VRChat\Cookies\Library", FileMode.Create, FileAccess.Write, FileShare.Write))
            {
                using (var stream = new BinaryWriter(file))
                {
                    stream.Write(1);
                    //
                    stream.Write(2);
                    //
                    stream.Write(1);
                    stream.Write("__cfduid"); // Name
                    stream.Write("d79ac88ebe7a7425354928479faa681d31555427597"); // Value
                    stream.Write(Date.ToBinary());
                    stream.Write(LastAccess.ToBinary());
                    stream.Write(Expires.ToBinary());
                    stream.Write(-1L); // MaxAge
                    stream.Write(false); // IsSession
                    stream.Write("vrchat.cloud"); // Domain
                    stream.Write("/"); // Path
                    stream.Write(false); // IsSecure
                    stream.Write(true); // IsHttpOnly
                    //
                    stream.Write(1);
                    stream.Write("cf_clearance"); // Name
                    stream.Write("189b7767c1b2bd011b514f33a1587a88808174f2-1555431551-604800-250"); // Value
                    stream.Write(Date.ToBinary());
                    stream.Write(LastAccess.ToBinary());
                    stream.Write(Expires.ToBinary());
                    stream.Write(-1L); // MaxAge
                    stream.Write(false); // IsSession
                    stream.Write("vrchat.cloud"); // Domain
                    stream.Write("/"); // Path
                    stream.Write(false); // IsSecure
                    stream.Write(true); // IsHttpOnly
                }
            }
        }
    }

    public static class DESEncryption
    {
        private const int ITERATIONS = 1000;
        private const string PASSWORD = ""; // CENSORED :p

        public static byte[] Encrypt(string plainText)
        {
            using (var memoryStream = new MemoryStream())
            {
                var provider = new DESCryptoServiceProvider();
                provider.GenerateIV();
                memoryStream.Write(provider.IV, 0, provider.IV.Length);
                var key = new Rfc2898DeriveBytes(PASSWORD, provider.IV, ITERATIONS).GetBytes(8);
                using (var cryptoStream = new CryptoStream(memoryStream, provider.CreateEncryptor(key, provider.IV), CryptoStreamMode.Write))
                {
                    var bytes = Encoding.UTF8.GetBytes(plainText);
                    cryptoStream.Write(bytes, 0, bytes.Length);
                    cryptoStream.FlushFinalBlock();
                    return Encoding.ASCII.GetBytes(Convert.ToBase64String(memoryStream.ToArray()) + "\x00");
                }
            }
        }

        public static bool TryDecrypt(byte[] cipher, out string plain)
        {
            try
            {
                using (var memoryStream = new MemoryStream(Convert.FromBase64String(Encoding.ASCII.GetString(cipher, 0, cipher.Length - 1))))
                {
                    var salt = new byte[8];
                    memoryStream.Read(salt, 0, salt.Length);
                    var key = new Rfc2898DeriveBytes(PASSWORD, salt, ITERATIONS).GetBytes(8);
                    using (var stream = new CryptoStream(memoryStream, new DESCryptoServiceProvider().CreateDecryptor(key, salt), CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(stream))
                        {
                            plain = streamReader.ReadToEnd();
                            return true;
                        }
                    }
                }
            }
            catch
            {
            }
            plain = string.Empty;
            return false;
        }
    }
}