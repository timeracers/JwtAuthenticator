namespace JWT_Authentication_Service
{
    public interface IJWTClaimValidator
    {
        bool Validate(JWTPayload payload);
    }
}