using JwtAuthenticator;

namespace AuthenticatorTests
{
    public class JwtRejectsValidator : IJwtClaimValidator
    {
        public bool Validate(JwtPayload payload)
        {
            return false;
        }
    }
}
