using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ProxyAuthHelperTests
    {
        [Fact]
        public void HasSharedSecret_RejectsShortOrNull()
        {
            Assert.False(ProxyAuthHelper.HasSharedSecret(null));
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig { ProxySharedSecret = null }));
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig { ProxySharedSecret = "short" }));
            Assert.True(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig
            {
                ProxySharedSecret = "0123456789abcdef"
            }));
        }

        [Fact]
        public void TryApplyAuthHeaders_ProducesVerifiableHmac()
        {
            var secret = "test-shared-secret-32chars!!!!";
            var config = new ThreatReportingConfig { ProxySharedSecret = secret };
            var path = "/report/hash";
            var body = "{\"type\":\"hash\",\"value\":\"abc\"}";

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.test" + path);
            Assert.True(ProxyAuthHelper.TryApplyAuthHeaders(request, config, path, body));

            Assert.True(request.Headers.Contains("X-Sentinel-Timestamp"));
            Assert.True(request.Headers.Contains("X-Sentinel-Nonce"));
            Assert.True(request.Headers.Contains("X-Sentinel-Signature"));
            // v1.8.1 RT-CRIT-1: shared secret must never leave the process as a header
            Assert.False(request.Headers.Contains("X-Sentinel-Auth"));

            var ts = request.Headers.GetValues("X-Sentinel-Timestamp").First();
            var nonce = request.Headers.GetValues("X-Sentinel-Nonce").First();
            var sig = request.Headers.GetValues("X-Sentinel-Signature").First();

            // v2.0.8: timestamp.nonce.path.body
            var payload = ProxyAuthHelper.BuildSignaturePayload(ts, nonce, path, body);
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var expected = ConvertHex.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            Assert.Equal(expected, sig);
        }

        [Fact]
        public void CreateAuthenticatedPost_FailsWithoutSecret()
        {
            var config = new ThreatReportingConfig { ProxySharedSecret = "x" };
            var (req, err) = ProxyAuthHelper.CreateAuthenticatedPost(
                "https://example.test", "/lookup/vt", "{}", config);
            Assert.Null(req);
            Assert.NotNull(err);
        }

        [Fact]
        public void CreateAuthenticatedPost_SucceedsWithSecret()
        {
            var config = new ThreatReportingConfig
            {
                ProxySharedSecret = "long-enough-shared-secret"
            };
            var (req, err) = ProxyAuthHelper.CreateAuthenticatedPost(
                "https://example.test", "/lookup/vt", "{\"type\":\"hash\",\"value\":\"00\"}", config);
            Assert.Null(err);
            Assert.NotNull(req);
            req!.Dispose();
        }
    }
}
