# JwtAuthenticator
### A C# Json Web Token Authentication Library

[Nuget Package](https://www.nuget.org/packages/timeracers.JwtAuthenticator "timeracers.JwtAuthenticator")

To create an authenticator use
```c#
new Authenticator(IEncryptor encryptor, params IJwtClaimValidator[] claimValidaters)
```
For the encryptor you can either create a HmacEncryptor or create your own IEncryptor.
```c#
public interface IEncryptor
{
    string Name { get; }
    byte[] Encrypt(byte[] data);
}
```
For claim validation, you don't need to do anything if you just want to check expiration and not before.
Otherwise add IJwtClaimValidators.
```c#
public interface IJwtClaimValidator
{
    bool Validate(JwtPayload payload);
}
```

To verify a token use Authenticator's
```c#
public Tuple<Token, JwtPayload> Authenticate(string jwtString)
```
and check that Token is equal to Token.Verified.  
Note: The JwtPayload will be null if the jwtString was misformed which is indicated by the Token enum being Invalid.
