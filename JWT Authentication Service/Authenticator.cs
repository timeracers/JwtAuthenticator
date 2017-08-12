using JWT_Authentication_Service;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace JWT_Authentication_Service
{
    public class Authenticator
    {
        private HMAC _hash;
        private IJWTClaimValidator[] _claimValidaters;

        public Authenticator(string secret, params IJWTClaimValidator[] claimValidaters)
        {
            _hash = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            _claimValidaters = claimValidaters;
        }

        public Tuple<Authentication, JWTPayload> Authenticate(string jwtString)
        {
            var parts = jwtString.Split('.');
            if (parts.Length != 3 || !new Base64URLString(parts[0]).Validate() || !new Base64URLString(parts[1]).Validate())
                return new Tuple<Authentication, JWTPayload>(Authentication.BadSignatureOrToken, null);
            if (parts[2] != new Base64URLString(_hash.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + "." + parts[1]))))
                return new Tuple<Authentication, JWTPayload>(Authentication.BadSignatureOrToken, null);
            try
            {
                var header = JObject.Parse(Encoding.UTF8.GetString(new Base64URLString(parts[0]).GetBytes()));
                var payload = JObject.Parse(Encoding.UTF8.GetString(new Base64URLString(parts[1]).GetBytes()));
                try
                {
                    if (header["alg"].Value<string>() != "HS256" || header["typ"].Value<string>() != "JWT")
                        return new Tuple<Authentication, JWTPayload>(Authentication.BadSignatureOrToken, new JWTPayload(payload));
                    var jwtPayload = new JWTPayload(payload);
                    return new Tuple<Authentication, JWTPayload>(_claimValidaters.Any((v) => !v.Validate(jwtPayload))
                        ? Authentication.FailedClaimsValidation : Authentication.Authenticated, jwtPayload);
                }
                catch
                {
                    return new Tuple<Authentication, JWTPayload>(Authentication.BadSignatureOrToken, new JWTPayload(payload));
                }
            }
            catch
            {
                return new Tuple<Authentication, JWTPayload>(Authentication.BadSignatureOrToken, null);
            }
        }
    }
}
