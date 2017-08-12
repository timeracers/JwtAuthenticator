using Newtonsoft.Json.Linq;

namespace JWT_Authentication_Service.Special_JWT_Validators
{
    public class JWTHasUserIdValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return payload["userId"] != null && payload["userId"].Type == JTokenType.String;
        }
    }
}
