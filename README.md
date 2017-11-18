# JwtAuthenticator
### A C# Json Web Token Authentication Library
[Nuget: timeracers.JwtAuthenticator](https://www.nuget.org/packages/timeracers.JwtAuthenticator)

Have you ever seen a "Login with GitHub" button? Obviously they couldn't have simply passed the login credentials. That is where Json Web Tokens come into play. To make a valid JWT you need to know the server's secret. By sharing the secret with only some services, you allow those JWT distributors to create them while preventing random users from creating them. This library can validate a token, extract the payload from a token, check if a token is expired, and even allows custom claim validation.

### Sections
* [Examples](#examples)
* [Usage](#usage)
* [Building and Testing](#building-and-testing)

### Examples
This example will either greet you or state that you aren't authorized based upon the JWT.
```c#
String jwt = ...;
var auth = new AuthenticationWrapper(HmacEncryptor.CreateSha256("strings are easier to create then byte arrays"),
    new JwtSubjectValidator());
var authenticated = auth.Authenticate(jwt);
if (authenticated.Item1 == Token.Verified)
    Console.WriteLine("Welcome " + authenticated.Item2.Subject.ToObject<string>());
else
    Console.WriteLine("You are unauthorized.");
```
```c#
public void YourAuthenticate(string jwt) {
	var auth = new AuthenticationWrapper(HmacEncryptor.CreateSha256("strings are easier to create then byte arrays"), new JwtSubjectValidator());
    var authenticated = auth.Authenticate(jwt);
    //You can check the result like this
    //authenticated.Item1 == Token.Verified
}
```

```c#
String validJwtWithUserX = ...;
var auth = new AuthenticationWrapper(HmacEncryptor.CreateSha256("strings are easier to create then byte arrays"),
    new JwtSubjectValidator());
var authenticated = auth.Authenticate(jwt);
if (authenticated.Item1 == Token.Verified)
    Console.WriteLine("Welcome " + authenticated.Item2.Subject.ToObject<string>());
else
    Console.WriteLine("You are unauthorized.");
```

To see a project that uses it view my [Alert Center](https://github.com/timeracers/AlertCenter) project.

### Usage
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

### Building and Testing
If you don't have visual studio 2017 and don't want to download the whole thing then you can use just the devs tools with your preferred shell, examples are for command prompt with the active directory being the project folder.
```console
MSBuild /t:Restore
MSBuild /p:Configuration=Release "/p:Platform=Any CPU"
MSTest /testcontainer:AuthenticatorTests\bin\Release\AuthenticatorTests.dll
```
