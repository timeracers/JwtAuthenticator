using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using JwtAuthenticator;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Diagnostics;
using Newtonsoft.Json;
#if !NUGET
using JwtAuthenticator.SpecialJwtValidators;
#endif

namespace AuthenticatorTests
{
    [TestClass]
    public class Tests
    {
        private IEncryptor _encryptor;
        private Authenticator _authenticator;

        [TestInitialize]
        public void Initialize()
        {
            _encryptor = HmacEncryptor.CreateSha256("secret");
            _authenticator = new Authenticator(_encryptor);
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveMoreOrLessThen2Dots()
        {
            AssertInvalidToken(CreateAcceptableJwtToken().Replace(".", ""));
            AssertInvalidToken(CreateAcceptableJwtToken() + ".");
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInHeader()
        {
            AssertInvalidToken("+/pp..");
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInBody()
        {
            AssertInvalidToken(".+/.");
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInSignature()
        {
            AssertInvalidToken("../+");
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichHeaderIsNotJson()
        {
            var invalidJson = "{]";
            AssertInvalidToken(CreateJwtToken(invalidJson, CreateAcceptablePayload()));
        }


        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichPayloadIsNotJson()
        {
            var invalidJson = "{]";
            AssertInvalidToken(CreateJwtToken(CreateAcceptableHeader(_encryptor.Name), invalidJson));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichDoNotHaveRequiredProperties()
        {
            var header = new JObject();
            header["typ"] = "JWT";

            var result = Authenticate(CreateJwtToken(header, CreateAcceptablePayload()));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichHaveDifferingTypesOfProperties()
        {
            var header = new JObject();
            header["alg"] = 256;
            header["typ"] = "JWT";

            var result = Authenticate(CreateJwtToken(header, CreateAcceptablePayload()));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledJWT()
        {
            var header = new JObject();
            header["alg"] = "HS256";
            header["typ"] = "!JWT";

            var result = Authenticate(CreateJwtToken(header, CreateAcceptablePayload()));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledToUseTheSameEncryptionAlgorithm()
        {
            var encryptor = HmacEncryptor.CreateSha512("secret");
            var header = new JObject();
            header["alg"] = "HS256";
            header["typ"] = "JWT";

            var result = new Authenticator(encryptor).Authenticate(CreateJwtToken(header, CreateAcceptablePayload(), encryptor));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWithInvalidSignature()
        {
            var differingEncryptor = HmacEncryptor.CreateSha512("secret");
            var result = new Authenticator(_encryptor).Authenticate(CreateAcceptableJwtToken(differingEncryptor));
            AssertBadSignature(result);
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhenAnyValidatorRejectsPayload()
        {
            AssertFailedClaims(new Authenticator(_encryptor, new JwtRejectsValidator()).Authenticate(CreateAcceptableJwtToken()));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_AcceptValidTokensWhenAllValidatorsAcceptsPayload()
        {
            AssertSuccess(new Authenticator(_encryptor, new JwtAcceptsValidator()).Authenticate(CreateAcceptableJwtToken()));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_HasSamePayload()
        {
            var payload = new JwtPayload(CreateAcceptablePayload());
            var result = Authenticate(CreateAcceptableJwtToken());
            Assert.AreEqual(payload, result.Item2);
        }

#if !NUGET
        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectAnonymous()
        {
            Assert.IsFalse(new JwtHasUserIdValidator().Validate(new JwtPayload(new JObject())));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectDifferingUserIdType()
        {
            var payload = new JObject();
            payload["userId"] = 4692483;

            var result = new JwtHasUserIdValidator().Validate(new JwtPayload(payload));

            Assert.IsFalse(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_ElseAccept()
        {
            var payload = new JObject();
            payload["userId"] = "it's me a mario";

            var result = new JwtHasUserIdValidator().Validate(new JwtPayload(payload));

            Assert.IsTrue(result);
        }
#endif

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_RejectsExpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();

            var result = new JwtExpiresValidator().Validate(new JwtPayload(payload));

            Assert.IsFalse(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_AcceptsUnexpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();

            var result = new JwtExpiresValidator().Validate(new JwtPayload(payload));

            Assert.IsTrue(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_AcceptsNeverExpiringToken()
        {
            Assert.IsTrue(new JwtExpiresValidator().Validate(new JwtPayload(new JObject())));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void NotBeforeValidator_RejectsTokensWhichAreUsedBeforeSpecifiedTime()
        {
            var payload = new JObject();
            payload["nbf"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();

            var result = new JwtNotBeforeValidator().Validate(new JwtPayload(payload));

            Assert.IsFalse(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void NotBeforeValidator_AcceptsTokensWhichAreUsedAfterSpecifiedTime()
        {
            var payload = new JObject();
            payload["nbf"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();

            var result = new JwtNotBeforeValidator().Validate(new JwtPayload(payload));

            Assert.IsTrue(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void NotBeforeValidator_AcceptsTokensWithoutNotBeforeProperty()
        {
            Assert.IsTrue(new JwtNotBeforeValidator().Validate(new JwtPayload(new JObject())));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void SubjectValidator_AcceptsTokensWithSubjectProperty()
        {
            var payload = new JObject();
            payload["sub"] = Guid.Empty.ToString();

            var result = new JwtSubjectValidator().Validate(new JwtPayload(payload));

            Assert.IsTrue(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void SubjectValidator_RejectsTokensWithoutSubjectProperty()
        {
            Assert.IsFalse(new JwtSubjectValidator().Validate(new JwtPayload(new JObject())));
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_ExposesBaseObject()
        {
            var jobj = new JObject();
            jobj["something"] = "Gold Coin";

            var isEqual = jobj.Equals(new JwtPayload(jobj).Base);

            Assert.IsTrue(isEqual);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_IndexableLikeJObject()
        {
            var jobj = new JObject();
            jobj["something"] = "Gold Coin";

            var result = new JwtPayload(jobj)["something"].Value<string>();

            Assert.AreEqual(jobj["something"].Value<string>(), result);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_RegularPropertiesAreUnabbreviated()
        {
            var jobj = new JObject();
            jobj["iss"] = "johnDoeCorps";

            var result = new JwtPayload(jobj).Issuer.Value<string>();

            Assert.AreEqual("johnDoeCorps", result);
        }

        private Tuple<Token, JwtPayload> Authenticate(string token)
        {
            return _authenticator.Authenticate(token);
        }

        private void AssertInvalidToken(string token)
        {
            AssertAuthenticationResult(Token.Invalid, false, Authenticate(token));
        }

        private void AssertMismatchedHeaders(Tuple<Token, JwtPayload> actual)
        {
            AssertAuthenticationResult(Token.MismatchedHeaders, true, actual);
        }

        private void AssertBadSignature(Tuple<Token, JwtPayload> actual)
        {
            AssertAuthenticationResult(Token.BadSignature, true, actual);
        }

        private void AssertFailedClaims(Tuple<Token, JwtPayload> actual)
        {
            AssertAuthenticationResult(Token.BadClaims, true, actual);
        }

        private void AssertSuccess(Tuple<Token, JwtPayload> actual)
        {
            AssertAuthenticationResult(Token.Verified, true, actual);
        }

        private void AssertAuthenticationResult(Token expectedResult, bool hasPayload, Tuple<Token, JwtPayload> actual)
        {
            Assert.AreEqual(expectedResult, actual.Item1);
            Assert.AreEqual(hasPayload, actual.Item2 != null);
        }

        private string CreateAcceptableJwtToken()
        {
            return CreateAcceptableJwtToken(_encryptor);
        }

        private string CreateAcceptableJwtToken(IEncryptor encryptor)
        {
            return CreateJwtToken(CreateAcceptableHeader(encryptor.Name), CreateAcceptablePayload(), encryptor);
        }

        private string CreateJwtToken(object header, object payload)
        {
            return CreateJwtToken(header, payload, _encryptor);
        }

        private string CreateJwtToken(object header, object payload, IEncryptor encryptor)
        {
            var headerAndPayload = new Base64URLString(GetBytes(header.ToString())) + "."
                + new Base64URLString(GetBytes(payload.ToString()));
            return headerAndPayload + "." + new Base64URLString(encryptor.Encrypt(GetBytes(headerAndPayload)));
        }

        private JObject CreateAcceptableHeader(string algorithm)
        {
            var header = new JObject();
            header["alg"] = algorithm;
            header["typ"] = "JWT";
            return header;
        }

        private JObject CreateAcceptablePayload()
        {
            return new JObject();
        }

        private byte[] GetBytes(string secret)
        {
            return Encoding.UTF8.GetBytes(secret);
        }
    }
}
