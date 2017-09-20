using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JwtAuthenticator
{
    public class Authenticator
    {
        private IEncryptor _encrypter;
        private List<IJwtClaimValidator> _claimValidaters;

        private Authenticator(IEncryptor encrypter, List<IJwtClaimValidator> claimValidaters)
        {
            _encrypter = encrypter;
            _claimValidaters = new List<IJwtClaimValidator>(claimValidaters);
        }

        public Authenticator(IEncryptor encrypter, params IJwtClaimValidator[] claimValidaters)
            : this(encrypter, new List<IJwtClaimValidator>(claimValidaters)
                { ClaimValidator.CreateExpiresValidator(), ClaimValidator.CreateNotBeforeValidator() }) { }

        public static Authenticator CreateCustom(IEncryptor encrypter, params IJwtClaimValidator[] claimValidaters)
        {
            return new Authenticator(encrypter, claimValidaters.ToList());;
        }

        public Tuple<Token, JwtPayload> Authenticate(string jwtString)
        {
            Optional<Tuple<JObject, JwtPayload>> jwtHeaderAndPayload = TryConvertString(jwtString);
            if(!jwtHeaderAndPayload.HasValue)
                return new Tuple<Token, JwtPayload>(Token.Invalid, null);
            var header = jwtHeaderAndPayload.Value.Item1;
            var payload = jwtHeaderAndPayload.Value.Item2;

            if (!VerifySignature(jwtString.Split('.')))
                return new Tuple<Token, JwtPayload>(Token.BadSignature, payload);
            if (!ValidateHeaders(header))
                return new Tuple<Token, JwtPayload>(Token.MismatchedHeaders, payload);
            if (!ValidatePayload(payload))
                return new Tuple<Token, JwtPayload>(Token.BadClaims, payload);
            return new Tuple<Token, JwtPayload>(Token.Verified, payload);
        }

        private Optional<Tuple<JObject, JwtPayload>> TryConvertString(string jwtString)
        {
            var parts = jwtString.Split('.');
            if (parts.Length != 3)
                return new Optional<Tuple<JObject, JwtPayload>>();
            try
            {
                return new Optional<Tuple<JObject, JwtPayload>>(
                    new Tuple<JObject, JwtPayload>(
                        JObject.Parse(
                            Encoding.UTF8.GetString(
                                new Base64URLString(parts[0]).GetBytes())),
                        new JwtPayload(
                            JObject.Parse(
                                Encoding.UTF8.GetString(
                                    new Base64URLString(parts[1]).GetBytes())))));
            }
            catch
            {
                return new Optional<Tuple<JObject, JwtPayload>>();
            }
        }

        private bool VerifySignature(string[] parts)
        {
            return parts[2] == new Base64URLString(_encrypter.Encrypt(Encoding.UTF8.GetBytes(parts[0] + "." + parts[1])));
        }

        private bool ValidateHeaders(JObject header)
        {
            return header["alg"] != null && header["alg"].Type == JTokenType.String && header["alg"].Value<string>() == _encrypter.Name
                && header["typ"] != null && header["typ"].Type == JTokenType.String && header["typ"].Value<string>() == "JWT";
        }

        private bool ValidatePayload(JwtPayload payload)
        {
            return _claimValidaters.All((v) => v.Validate(payload));
        }
    }
}
