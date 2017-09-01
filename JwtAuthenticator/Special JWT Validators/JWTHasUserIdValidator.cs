using Newtonsoft.Json.Linq;

namespace JwtAuthenticator.Special_JWT_Validators
{
    public class JwtHasUserIdValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return payload["userId"] != null && payload["userId"].Type == JTokenType.String;
        }
    }
}
