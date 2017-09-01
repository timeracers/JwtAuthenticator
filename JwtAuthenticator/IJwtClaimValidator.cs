namespace JwtAuthenticator
{
    public interface IJWTClaimValidator
    {
        bool Validate(JWTPayload payload);
    }
}