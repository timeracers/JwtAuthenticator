#if !Nuget
using Newtonsoft.Json.Linq;

namespace JwtAuthenticator.SpecialJwtValidators
{
    public class JwtHasUserIdValidator : IJwtClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return payload.Validate<string>(JTokenType.String, "userId", (id) => true);
        }
    }
}
#endif