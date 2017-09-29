    JwtAuthenticator
To create an authenticator use
  new Authenticator(IEncryptor encryptor, params IJwtClaimValidator[] claimValidaters)
For the encryptor you can either use HmacEncryptor's methods or create your own IEncryptor.
An IEncryptor needs to have a name and a encrypt method which takes a byte[] and returns a byte[].
For claim validation you don't need to do anything if you just want to check expiration or not before.
If you want to add more claim validaters then you just need to supply a validate method which takes a JwtPayload and returns a bool.
With the authenticator you can authenticate with the jwt which returns both the result, and the JwtPayload if it was properly formatted.
