using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JWTRejectsValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return false;
        }
    }
}
