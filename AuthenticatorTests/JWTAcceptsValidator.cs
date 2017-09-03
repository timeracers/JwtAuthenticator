using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JwtAcceptsValidator : IJwtClaimValidator
    {
        public bool Validate(JWTPayload payload)
        {
            return true;
        }
    }
}
