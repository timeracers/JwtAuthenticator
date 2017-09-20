using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JwtAcceptsValidator : IJwtClaimValidator
    {
        public bool Validate(JwtPayload payload)
        {
            return true;
        }
    }
}
