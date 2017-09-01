namespace JwtAuthenticator
{
    public interface IEncryptor
    {
        string Name { get; }
        byte[] Encrypt(byte[] data);
    }
}