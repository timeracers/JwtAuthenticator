namespace JwtAuthenticator
{
    public interface IJwtClaimValidator
    {
        bool Validate(JwtPayload payload);
    }
}