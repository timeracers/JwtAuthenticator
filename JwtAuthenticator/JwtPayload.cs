using Newtonsoft.Json.Linq;
using System;

namespace JwtAuthenticator
{
    public class JwtPayload
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

        public JwtPayload(JObject payload)
        {
            Base = payload;
        }

        public bool Validate<T>(JTokenType type, string property, Predicate<T> condition)
        {
            return Validate(type, this[property], condition);
        }

        public bool Validate<T>(JTokenType type, JToken property, Predicate<T> condition)
        {
            return property != null && ValidateIfPresent(type, property, condition);
        }

        public bool ValidateIfPresent<T>(JTokenType type, string property, Predicate<T> condition)
        {
            return ValidateIfPresent(type, this[property], condition);
        }

        public bool ValidateIfPresent<T>(JTokenType type, JToken property, Predicate<T> condition)
        {
            return property == null || property.Type == type && condition(property.Value<T>());
        }

        public override bool Equals(object obj)
        {
            return obj is JwtPayload && this.ToString().Equals(obj.ToString());
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

    public class JwtExpiresValidator : IJwtClaimValidator
    {
        public bool Validate(JwtPayload payload)
        {
            return payload.ValidateIfPresent<long>(JTokenType.Integer, "exp", (t) => t >= DateTimeOffset.Now.ToUnixTimeSeconds());
        }
    }

    public class JwtNotBeforeValidator : IJwtClaimValidator
    {
        public bool Validate(JwtPayload payload)
        {
            return payload.ValidateIfPresent<long>(JTokenType.Integer, "nbf", (t) => DateTimeOffset.Now.ToUnixTimeSeconds() >= t);
        }
    }

    public static class ClaimValidator
    {
        public static JwtExpiresValidator CreateExpiresValidator()
        {
            return new JwtExpiresValidator();
        }

        public static JwtNotBeforeValidator CreateNotBeforeValidator()
        {
            return new JwtNotBeforeValidator();
        }
    }
}
