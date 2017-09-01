using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JWTAcceptsValidator : IJWTClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return true;
        }
    }
}
