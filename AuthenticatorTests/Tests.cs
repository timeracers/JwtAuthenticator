using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using JwtAuthenticator;
using System.Text;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using JwtAuthenticator.Special_JWT_Validators;

namespace AuthenticatorTests
{
    [TestClass]
    public class Tests
    {
        private IEncryptor _encryptor;

        [TestInitialize]
        public void Initilize()
        {
            _encryptor = HmacShaEncryptor.CreateSha256("secret");
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveMoreOrLessThen2Dots()
        {
            var notEnoughDots = new Authenticator(_encryptor).Authenticate(CreateAcceptableJWTToken(_encryptor) + ".");
            var tooManyDots = new Authenticator(_encryptor).Authenticate(CreateAcceptableJWTToken(_encryptor).Replace(".", ""));

            AssertInvalidToken(notEnoughDots);
            AssertInvalidToken(tooManyDots);
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInHeader()
        {
            AssertInvalidToken(new Authenticator(_encryptor).Authenticate("+/pp.."));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInBody()
        {
            AssertInvalidToken(new Authenticator(_encryptor).Authenticate(".+/."));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInSignature()
        {
            AssertInvalidToken(new Authenticator(_encryptor).Authenticate("../+"));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichHeaderIsNotJson()
        {
            var invalidJson = "{]";
            var result = new Authenticator(_encryptor).Authenticate(CreateJWTToken(invalidJson, CreateAcceptablePayload(), _encryptor));
            AssertInvalidToken(result);
        }


        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichPayloadIsNotJson()
        {
            var invalidJson = "{]";
            var result = new Authenticator(_encryptor).Authenticate(CreateJWTToken(CreateAcceptableHeader(_encryptor.Name), invalidJson, _encryptor));
            AssertInvalidToken(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichDoNotHaveRequiredProperties()
        {
            var header = new JObject();
            header["typ"] = "JWT";

            var result = new Authenticator(_encryptor).Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), _encryptor));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichHaveDifferingTypesOfProperties()
        {
            var header = new JObject();
            header["alg"] = 256;
            header["typ"] = "JWT";

            var result = new Authenticator(_encryptor).Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), _encryptor));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledJWT()
        {
            var header = new JObject();
            header["alg"] = "HS256";
            header["typ"] = "!JWT";

            var result = new Authenticator(_encryptor).Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), _encryptor));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledToUseTheSameEncryptionAlgorithm()
        {
            var encryptor = HmacShaEncryptor.CreateSha512("secret");
            var header = new JObject();
            header["alg"] = "HS256";
            header["typ"] = "JWT";

            var result = new Authenticator(encryptor).Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), encryptor));

            AssertMismatchedHeaders(result);
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWithInvalidSignature()
        {
            var differingEncryptor = HmacShaEncryptor.CreateSha512("secret");
            var result = new Authenticator(_encryptor).Authenticate(CreateAcceptableJWTToken(differingEncryptor));
            AssertBadSignature(result);
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhenAnyValidatorRejectsPayload()
        {
            var payload = new JObject();
            payload["userId"] = "It's me a mario";
            payload["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();
            var authenticator = new Authenticator(_encryptor, new JWTRejectsValidator());

            var result = authenticator.Authenticate(CreateJWTToken(CreateAcceptableHeader(_encryptor.Name), payload, _encryptor));

            AssertFailedClaims(result);
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_AcceptValidTokensWhenAllValidatorsAcceptsPayload()
        {
            AssertSuccess(new Authenticator(_encryptor, new JWTAcceptsValidator()).Authenticate(CreateAcceptableJWTToken(_encryptor)));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_HasSamePayload()
        {
            var payload = new JWTPayload(CreateAcceptablePayload());
            var result = new Authenticator(_encryptor).Authenticate(CreateAcceptableJWTToken(_encryptor));
            Assert.AreEqual(payload, result.Item2);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectAnonymous()
        {
            Assert.IsFalse(new JwtHasUserIdValidator().Validate(new JWTPayload(new JObject())));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectDifferingUserIdType()
        {
            var payload = new JObject();
            payload["userId"] = 4692483;

            var result = new JwtHasUserIdValidator().Validate(new JWTPayload(payload));

            Assert.IsFalse(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_ElseAccept()
        {
            var payload = new JObject();
            payload["userId"] = "it's me a mario";

            var result = new JwtHasUserIdValidator().Validate(new JWTPayload(payload));

            Assert.IsTrue(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_RejectsExpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();

            var result = new JWTExpiresValidator().Validate(new JWTPayload(payload));

            Assert.IsFalse(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_AcceptsUnexpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();

            var result = new JWTExpiresValidator().Validate(new JWTPayload(payload));

            Assert.IsTrue(result);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_AcceptsNeverExpiringToken()
        {
            Assert.IsTrue(new JWTExpiresValidator().Validate(new JWTPayload(new JObject())));
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_ExposesBaseObject()
        {
            var jobj = new JObject();
            jobj["something"] = "Gold Coin";

            var isEqual = jobj.Equals(new JWTPayload(jobj).Base);

            Assert.IsTrue(isEqual);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_IndexableLikeJObject()
        {
            var jobj = new JObject();
            jobj["something"] = "Gold Coin";

            var result = new JWTPayload(jobj)["something"].Value<string>();

            Assert.AreEqual(jobj["something"].Value<string>(), result);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_RegularPropertiesAreUnabbreviated()
        {
            var jobj = new JObject();
            jobj["iss"] = "johnDoeCorps";

            var result = new JWTPayload(jobj).Issuer.Value<string>();

            Assert.AreEqual("johnDoeCorps", result);
        }

        private void AssertInvalidToken(Tuple<Token, JWTPayload> actual)
        {
            AssertAuthenticateResult(Token.Invalid, false, actual);
        }

        private void AssertMismatchedHeaders(Tuple<Token, JWTPayload> actual)
        {
            AssertAuthenticateResult(Token.MismatchedHeaders, true, actual);
        }

        private void AssertBadSignature(Tuple<Token, JWTPayload> actual)
        {
            AssertAuthenticateResult(Token.BadSignature, true, actual);
        }

        private void AssertFailedClaims(Tuple<Token, JWTPayload> actual)
        {
            AssertAuthenticateResult(Token.BadClaims, true, actual);
        }

        private void AssertSuccess(Tuple<Token, JWTPayload> actual)
        {
            AssertAuthenticateResult(Token.Verified, true, actual);
        }

        private void AssertAuthenticateResult(Token expectedResult, bool hasPayload, Tuple<Token, JWTPayload> actual)
        {
            Assert.AreEqual(expectedResult, actual.Item1);
            Assert.AreEqual(hasPayload, (actual.Item2 != null));
        }

        private string CreateAcceptableJWTToken(IEncryptor encryptor)
        {
            return CreateJWTToken(CreateAcceptableHeader(encryptor.Name), CreateAcceptablePayload(), encryptor);
        }

        private string CreateJWTToken(object header, object payload, IEncryptor encryptor)
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
            var payload = new JObject();
            return payload;
        }

        private byte[] GetBytes(string secret)
        {
            return Encoding.UTF8.GetBytes(secret);
        }
    }
}
