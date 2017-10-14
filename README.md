# JwtAuthenticator
### A C# Json Web Token Authentication Library

[Nuget Package](https://www.nuget.org/packages/timeracers.JwtAuthenticator "timeracers.JwtAuthenticator")

To create an authenticator use
```c#
new Authenticator(IEncryptor encryptor, params IJwtClaimValidator[] claimValidaters)
```
For the encryptor you can either create a HmacEncryptor or create your own encryptor that fulfills
```c#
public interface IEncryptor
{
    string Name { get; }
    byte[] Encrypt(byte[] data);
}
```
For claim validation, you don't need to do anything if you just want to check expiration and not before.
To add extra claim validators they need to implement
```c#
public interface IJwtClaimValidator
{
    bool Validate(JwtPayload payload);
}
```

To verify a token use Authenticator's authenticate method and confirm that the Token is equal to Token.Verified.
```c#
public Tuple<Token, JwtPayload> Authenticate(string jwtString)
```
Note: The JwtPayload will be null if the jwtString was misformed which is indicated by the Token being Token.Invalid.
