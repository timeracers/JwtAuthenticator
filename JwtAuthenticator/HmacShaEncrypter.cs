using System.Security.Cryptography;
using System.Text;

namespace JwtAuthenticator
{
    public class HmacShaEncryptor : IEncryptor
    {
        private HMAC _hmac;

        public static HmacShaEncryptor CreateSha256(string secret)
        {
            return new HmacShaEncryptor(new HMACSHA256(Encoding.UTF8.GetBytes(secret)), "HS256");
        }

        public static HmacShaEncryptor CreateSha384(string secret)
        {
            return new HmacShaEncryptor(new HMACSHA384(Encoding.UTF8.GetBytes(secret)), "HS384");
        }

        public static HmacShaEncryptor CreateSha512(string secret)
        {
            return new HmacShaEncryptor(new HMACSHA512(Encoding.UTF8.GetBytes(secret)), "HS512");
        }

        public HmacShaEncryptor(HMAC hmac, string name)
        {
            _hmac = hmac;
            Name = name;
        }

        public string Name { get; private set; }

        public byte[] Encrypt(byte[] data)
        {
            return _hmac.ComputeHash(data);
        }
    }
}
