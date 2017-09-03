using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JwtRejectsValidator : IJwtClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return false;
        }
    }
}
