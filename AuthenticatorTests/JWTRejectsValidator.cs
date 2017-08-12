using JWT_Authentication_Service;

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
