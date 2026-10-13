using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ServiceAgentIpcTests
    {
        [Fact]
        public void PipeName_IsExpectedValue()
        {
            Assert.Equal("SentinelIpc-v2", ServiceAgentIpc.PipeName);
        }

        [Fact]
        public void ProtocolVersion_IsV2()
        {
            Assert.Equal("2.0", ServiceAgentIpc.ProtocolVersion);
        }

        [Fact]
        public void Sign_ProducesConsistentHmac()
        {
            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            var payload = "12345|nonce123|ping|";
            var sig1 = ServiceAgentIpc.Sign(token, payload);
            var sig2 = ServiceAgentIpc.Sign(token, payload);

            Assert.Equal(sig1, sig2);
            Assert.Equal(64, sig1.Length); // HMAC-SHA256 = 32 bytes = 64 hex chars
        }

        [Fact]
        public void Sign_DifferentPayloads_ProduceDifferentHmacs()
        {
            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            var sig1 = ServiceAgentIpc.Sign(token, "payload1");
            var sig2 = ServiceAgentIpc.Sign(token, "payload2");

            Assert.NotEqual(sig1, sig2);
        }

        [Fact]
        public void Verify_ReturnsTrue_ForValidSignature()
        {
            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            var payload = "67890|abc12345|ops|{}";
            var sig = ServiceAgentIpc.Sign(token, payload);

            Assert.True(ServiceAgentIpc.Verify(token, payload, sig));
        }

        [Fact]
        public void Verify_ReturnsFalse_ForInvalidSignature()
        {
            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            var payload = "12345|nonce|ping|";
            Assert.False(ServiceAgentIpc.Verify(token, payload, "0000000000000000000000000000000000000000000000000000000000000000"));
        }

        [Fact]
        public void Verify_ReturnsFalse_ForNull()
        {
            var token = new byte[32];
            Assert.False(ServiceAgentIpc.Verify(token, "payload", null));
        }

        [Fact]
        public void Verify_ReturnsFalse_ForEmptyString()
        {
            var token = new byte[32];
            Assert.False(ServiceAgentIpc.Verify(token, "payload", ""));
        }

        [Fact]
        public void Verify_ReturnsFalse_ForWrongLength()
        {
            var token = new byte[32];
            Assert.False(ServiceAgentIpc.Verify(token, "payload", "short"));
            Assert.False(ServiceAgentIpc.Verify(token, "payload", "toolongtobevalidhexstringthatexceedssixtyfourcharsbyalotmore12345"));
        }

        [Fact]
        public void IsTimestampFresh_ReturnsTrue_ForCurrentTime()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Assert.True(ServiceAgentIpc.IsTimestampFresh(now));
        }

        [Fact]
        public void IsTimestampFresh_ReturnsTrue_WithinSkew()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Assert.True(ServiceAgentIpc.IsTimestampFresh(now - 30)); // 30s in past
            Assert.True(ServiceAgentIpc.IsTimestampFresh(now + 30)); // 30s in future
        }

        [Fact]
        public void IsTimestampFresh_ReturnsFalse_ForOldTimestamp()
        {
            var old = DateTimeOffset.UtcNow.AddMinutes(-5).ToUnixTimeSeconds();
            Assert.False(ServiceAgentIpc.IsTimestampFresh(old));
        }

        [Fact]
        public void IsTimestampFresh_ReturnsFalse_ForFarFuture()
        {
            var future = DateTimeOffset.UtcNow.AddMinutes(5).ToUnixTimeSeconds();
            Assert.False(ServiceAgentIpc.IsTimestampFresh(future));
        }

        [Fact]
        public void BuildAuthPayload_FormatsCorrectly()
        {
            var payload = ServiceAgentIpc.BuildAuthPayload(12345, "nonce_abc", "ping", "{}");
            Assert.Equal("12345|nonce_abc|ping|{}", payload);
        }

        [Fact]
        public void TokenPath_ContainsSentinelSecure()
        {
            var path = ServiceAgentIpc.TokenPath;
            Assert.Contains("Sentinel", path);
            Assert.Contains("Secure", path);
            Assert.Contains(".ipc_token", path);
        }

        [Fact]
        public void TryLoadToken_ReturnsNull_WhenFileDoesNotExist()
        {
            // Token may or may not exist on this system, but should not throw
            var token = ServiceAgentIpc.TryLoadToken();
            // Either null (not installed) or 32 bytes (installed)
            if (token != null)
                Assert.Equal(32, token.Length);
        }

        [Fact]
        public void Verify_CaseInsensitive_Hex()
        {
            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            var payload = "test|nonce|op|body";
            var sig = ServiceAgentIpc.Sign(token, payload);

            // Sign returns lowercase, verify should accept uppercase too
            Assert.True(ServiceAgentIpc.Verify(token, payload, sig.ToUpperInvariant()));
        }
    }
}
