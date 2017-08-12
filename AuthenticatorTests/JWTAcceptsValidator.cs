using JWT_Authentication_Service;

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
