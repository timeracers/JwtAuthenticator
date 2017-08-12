using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using JWT_Authentication_Service;
using System.Web;
using System.Text;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Security.Cryptography;
using JWT_Authentication_Service.Special_JWT_Validators;

namespace AuthenticatorTests
{
    [TestClass]
    public class Tests
    {

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveMoreOrLessThen2Dots()
        {
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(CreateAcceptableJWTToken("") + "."));
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(CreateAcceptableJWTToken("").Replace(".", "")));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInHeader()
        {
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate("+/pp.."));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInBody()
        {
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(".+/."));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensThatHaveInvalidBase64UrlCharactersInSignature()
        {
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate("../+"));
        }

        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichHeaderIsNotJson()
        {

            var invalidJson = "{]";
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(CreateJWTToken(invalidJson, CreateAcceptablePayload(), "")));
        }


        [TestCategory("InvalidFormat")]
        [TestMethod]
        public void Authenticated_RejectTokensWhichPayloadIsNotJson()
        {
            var invalidJson = "{]";
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(CreateJWTToken(CreateAcceptableHeader(), invalidJson, "")));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichDoNotHaveRequiredProperties()
        {
            var header = new JObject();
            header["typ"] = "JWT";
            AssertBadSignatureOrTokenWithPayload(new Authenticator("").Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), "")));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichHaveDifferingTypesOfProperties()
        {
            var header = new JObject();
            header["alg"] = 256;
            header["typ"] = "JWT";
            AssertBadSignatureOrTokenWithPayload(new Authenticator("").Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), "")));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledJWT()
        {
            var header = new JObject();
            header["alg"] = "HS256";
            header["typ"] = "!JWT";
            AssertBadSignatureOrTokenWithPayload(new Authenticator("").Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), "")));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhichAreNotLabelledHS256()
        {
            var header = new JObject();
            header["alg"] = "RS256";
            header["typ"] = "JWT";
            AssertBadSignatureOrTokenWithPayload(new Authenticator("").Authenticate(CreateJWTToken(header, CreateAcceptablePayload(), "")));
        }

        [TestCategory("UnacceptableJWT")]
        [TestMethod]
        public void Authenticated_RejectTokensWithInvalidSignature()
        {
            AssertBadSignatureOrTokenWithoutPayload(new Authenticator("").Authenticate(CreateAcceptableJWTToken("differing secret")));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_RejectButHasPayloadForTokensWhenAnyValidatorRejectsPayload()
        {
            var payload = new JObject();
            payload["userId"] = "It's me a mario";
            payload["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();
            AssertFailedClaims(new Authenticator("", new JWTRejectsValidator()).Authenticate(
                CreateJWTToken(CreateAcceptableHeader(), payload, "")));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_AcceptValidTokensWhenAllValidatorsAcceptsPayload()
        {
            AssertSuccess(new Authenticator("s", new JWTAcceptsValidator()).Authenticate(CreateAcceptableJWTToken("s")));
        }

        [TestCategory("ValidJWT")]
        [TestMethod]
        public void Authenticated_HasSamePayload()
        {
            var payload = new Authenticator("s").Authenticate(CreateAcceptableJWTToken("s")).Item2;
            new JWTPayload(CreateAcceptablePayload()).Equals(payload);
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectAnonymous()
        {
            Assert.IsFalse(new JWTHasUserIdValidator().Validate(new JWTPayload(new JObject())));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_RejectDifferingUserIdType()
        {
            var payload = new JObject();
            payload["userId"] = 4692483;
            Assert.IsFalse(new JWTHasUserIdValidator().Validate(new JWTPayload(payload)));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void UserIdValidator_ElseAccept()
        {
            var payload = new JObject();
            payload["userId"] = "it's me a mario";
            Assert.IsTrue(new JWTHasUserIdValidator().Validate(new JWTPayload(payload)));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_RejectsExpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(-1).ToUnixTimeSeconds();
            Assert.IsFalse(new JWTExpiresValidator().Validate(new JWTPayload(payload)));
        }

        [TestCategory("Validator")]
        [TestMethod]
        public void ExpiresValidator_AcceptsUnexpiredToken()
        {
            var payload = new JObject();
            payload["exp"] = DateTimeOffset.Now.AddDays(1).ToUnixTimeSeconds();
            Assert.IsTrue(new JWTExpiresValidator().Validate(new JWTPayload(payload)));
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
            Assert.AreEqual(jobj, new JWTPayload(jobj).Base);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_IndexableLikeJObject()
        {
            var jobj = new JObject();
            jobj["something"] = "Gold Coin";
            Assert.AreEqual(jobj["something"].Value<string>(), new JWTPayload(jobj)["something"].Value<string>());
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_RegularPropertiesReturnNoValueIfNotPresent()
        {
            var jobj = new JObject();
            Assert.IsTrue(!new JWTPayload(jobj).Issuer.HasValue);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_RegularPropertiesReturnNoValueIfDifferingFormat()
        {
            var jobj = new JObject();
            jobj["iss"] = 123;
            Assert.IsTrue(!new JWTPayload(jobj).Issuer.HasValue);
        }

        [TestCategory("Payload")]
        [TestMethod]
        public void Payload_ElseRegularPropertiesReturnValue()
        {
            var jobj = new JObject();
            jobj["iss"] = "johnDoeCorps";
            Assert.IsTrue(new JWTPayload(jobj).Issuer.Value == "johnDoeCorps");
        }

        private void AssertBadSignatureOrTokenWithoutPayload(Tuple<Authentication, JWTPayload> actual)
        {
            AssertAuthenticateResult(Authentication.BadSignatureOrToken, false, actual);
        }

        private void AssertBadSignatureOrTokenWithPayload(Tuple<Authentication, JWTPayload> actual)
        {
            AssertAuthenticateResult(Authentication.BadSignatureOrToken, true, actual);
        }

        private void AssertFailedClaims(Tuple<Authentication, JWTPayload> actual)
        {
            AssertAuthenticateResult(Authentication.FailedClaimsValidation, true, actual);
        }

        private void AssertSuccess(Tuple<Authentication, JWTPayload> actual)
        {
            AssertAuthenticateResult(Authentication.Authenticated, true, actual);
        }

        private void AssertAuthenticateResult(Authentication expectedResult, bool hasPayload, Tuple<Authentication, JWTPayload> actual)
        {
            Assert.AreEqual(expectedResult, actual.Item1);
            Assert.AreEqual(hasPayload, (actual.Item2 != null));
        }

        private string CreateAcceptableJWTToken(string secret)
        {
            return CreateJWTToken(CreateAcceptableHeader(), CreateAcceptablePayload(), secret);
        }

        private string CreateJWTToken(object header, object payload, string secret)
        {
            var headerAndPayload = new Base64URLString(GetBytes(header.ToString())) + "."
                + new Base64URLString(GetBytes(payload.ToString()));
            return headerAndPayload + "." + new Base64URLString(new HMACSHA256(GetBytes(secret)).ComputeHash(GetBytes(headerAndPayload)));
        }

        private JObject CreateAcceptableHeader()
        {
            var header = new JObject();
            header["alg"] = "HS256";
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
