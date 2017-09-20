#if !NUGET
using Newtonsoft.Json.Linq;

namespace JwtAuthenticator.SpecialJwtValidators
{
    public class JwtHasUserIdValidator : IJwtClaimValidator
    {
        public bool Validate(JwtPayload payload)
        {
            return payload.Validate<string>(JTokenType.String, "userId", (id) => true);
        }
    }
}
#endif