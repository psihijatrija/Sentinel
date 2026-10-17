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
        public void HasSharedSecret_RejectsAllLegacyConfiguration()
        {
            Assert.False(ProxyAuthHelper.HasSharedSecret(null));
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig { ProxySharedSecret = null }));
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig { ProxySharedSecret = "short" }));
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig
            {
                ProxySharedSecret = "0123456789abcdef"
            }));
        }

        [Fact]
        public void TryApplyAuthHeaders_OfflineConfigCannotAuthorizeTransport()
        {
            var config = new ThreatReportingConfig { Enabled = true, ProxySharedSecret = "test-shared-secret-32chars!!!!" };
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.test/report/hash");
            Assert.False(ProxyAuthHelper.TryApplyAuthHeaders(request, config, "/report/hash", "{}"));
            Assert.Empty(request.Headers);
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
        public void CreateAuthenticatedPost_FailsClosedEvenWithLegacySecret()
        {
            var config = new ThreatReportingConfig
            {
                ProxySharedSecret = "long-enough-shared-secret"
            };
            var (req, err) = ProxyAuthHelper.CreateAuthenticatedPost(
                "https://example.test", "/lookup/vt", "{\"type\":\"hash\",\"value\":\"00\"}", config);
            Assert.NotNull(err);
            Assert.Null(req);
        }
    }
}
