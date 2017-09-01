namespace JwtAuthenticator
{
    public enum Token
    {
        Invalid,
        BadSignature,
        MismatchedHeaders,
        BadClaims,
        Verified
    }
}