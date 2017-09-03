namespace JwtAuthenticator
{
    public interface IJwtClaimValidator
    {
        bool Validate(JWTPayload payload);
    }
}