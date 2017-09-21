using System.Security.Cryptography;
using System.Text;

namespace JwtAuthenticator
{
    public class HmacEncryptor : IEncryptor
    {
        public string Name { get; private set; }

        private HMAC _hmac;

        public static HmacEncryptor CreateSha256(string secret)
        {
            return new HmacEncryptor(new HMACSHA256(Encoding.UTF8.GetBytes(secret)), "HS256");
        }

        public static HmacEncryptor CreateSha384(string secret)
        {
            return new HmacEncryptor(new HMACSHA384(Encoding.UTF8.GetBytes(secret)), "HS384");
        }

        public static HmacEncryptor CreateSha512(string secret)
        {
            return new HmacEncryptor(new HMACSHA512(Encoding.UTF8.GetBytes(secret)), "HS512");
        }

        public HmacEncryptor(HMAC hmac, string name)
        {
            _hmac = hmac;
            Name = name;
        }

        public byte[] Encrypt(byte[] data)
        {
            return _hmac.ComputeHash(data);
        }
    }
}
