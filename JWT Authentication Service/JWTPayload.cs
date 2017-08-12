using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;

namespace JWT_Authentication_Service
{
#pragma warning disable CS0659 // Type overrides Object.Equals(object o) but does not override Object.GetHashCode()
    public class JWTPayload
#pragma warning restore CS0659 // Type overrides Object.Equals(object o) but does not override Object.GetHashCode()
    {
        public JObject Base { get; private set; }
        public Optional<string> Subject { get { return TryGetStringOf("sub"); } }
        public Optional<long> Expires { get { return TryGetLongOf("exp"); } }
        public Optional<string> Audience { get { return TryGetStringOf("aud"); } }
        public Optional<string> UniqueTokenIdentifier { get { return TryGetStringOf("jti"); } }
        public Optional<long> NotBefore { get { return TryGetLongOf("nbf"); } }
        public Optional<string> Issuer { get { return TryGetStringOf("iss"); } }
        public Optional<string> Issued { get { return TryGetStringOf("iat"); } }

        public JToken this[string propertyName] { get { return Base[propertyName]; }}

        public JWTPayload(JObject payload)
        {
            Base = payload;
        }

        public override bool Equals(object obj)
        {
            return obj is JWTPayload && this.ToString().Equals(obj.ToString());
        }

        public override string ToString()
        {
            return Base.ToString();
        }

        private Optional<string> TryGetStringOf(string property)
        {
            var prop = Base[property];
            return prop != null && prop.Type == JTokenType.String ? new Optional<string>(prop.Value<string>()) : new Optional<string>();
        }

        private Optional<long> TryGetLongOf(string property)
        {
            var prop = Base[property];
            return prop != null && prop.Type == JTokenType.Integer ? new Optional<long>(prop.Value<long>()) : new Optional<long>();
        }
    }

    public class JWTExpiresValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return payload["exp"] == null || payload.Expires.HasValue && payload.Expires.Value >= DateTimeOffset.Now.ToUnixTimeSeconds();
        }
    }
}
