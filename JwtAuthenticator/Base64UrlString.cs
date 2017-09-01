using System;
using System.Text.RegularExpressions;

namespace JwtAuthenticator
{
    public class Base64URLString
    {
        private string _value;

        public Base64URLString(string s)
        {
            _value = s;
        }

        public Base64URLString(byte[] bytes)
        {
            _value = Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        public bool Validate()
        {
            return Regex.IsMatch(_value, @"^[a-zA-Z0-9_-]*$", RegexOptions.None);
        }

        public byte[] GetBytes()
        {
            var s = _value.Replace('-', '+').Replace('_', '/');
            while (s.Length % 4 != 0)
                s += "=";
            return Convert.FromBase64String(s);
        }

        public static implicit operator string(Base64URLString s)
        {
            return s._value;
        }
    }
}
