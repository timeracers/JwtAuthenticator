using Newtonsoft.Json.Linq;
using System;

namespace JwtAuthenticator
{
    public class JWTPayload
    {
        public JObject Base { get; private set; }
        public JToken this[string propertyName] { get { return Base[propertyName]; }}
        public JToken Subject { get { return this["sub"]; } }
        public JToken Expires { get { return this["exp"]; } }
        public JToken Audience { get { return this["aud"]; } }
        public JToken UniqueTokenIdentifier { get { return this["jti"]; } }
        public JToken NotBefore { get { return this["nbf"]; } }
        public JToken Issuer { get { return this["iss"]; } }
        public JToken Issued { get { return this["iat"]; } }

        public JWTPayload(JObject payload)
        {
            Base = payload;
        }

        public override bool Equals(object obj)
        {
            return obj is JWTPayload && this.ToString().Equals(obj.ToString());
        }

        public override int GetHashCode()
        {
            return Base.GetHashCode();
        }

        public override string ToString()
        {
            return Base.ToString();
        }
    }

    public class JWTExpiresValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return payload["exp"] == null ||
                (payload.Expires.Type == JTokenType.Integer && payload.Expires.Value<long>() >= DateTimeOffset.Now.ToUnixTimeSeconds());
        }
    }

    public static class ClaimValidator
    {
        public static JWTExpiresValidator CreateExpiresValidator()
        {
            return new JWTExpiresValidator();
        }
    }
}
