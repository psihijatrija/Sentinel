using System;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public sealed class EvidenceAnchorClientTests
    {
        private sealed class Handler : HttpMessageHandler
        {
            public string Body = "";
            public int Calls;
            public HttpStatusCode Status = HttpStatusCode.OK;
            public string Reply = "{\"success\":true,\"receipt\":\"evidence:v1:" + new string('a', 64) + "\"}";
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                token.ThrowIfCancellationRequested();
                Calls++;
                Body = await request.Content!.ReadAsStringAsync();
                Assert.True(request.Headers.Contains("X-Sentinel-Signature"));
                return new HttpResponseMessage(Status) { Content = new StringContent(Reply) };
            }
        }

        private static string EphemeralKey()
        {
            var bytes = new byte[32];
            using var random = RandomNumberGenerator.Create();
            random.GetBytes(bytes);
            return Convert.ToBase64String(bytes);
        }

        [Fact]
        public async Task PublicCompatibilityCredential_DoesNotEnableEvidenceWrites()
        {
            using var handler = new Handler();
            using var http = new HttpClient(handler);
            var config = new ThreatReportingConfig { ProxySharedSecret = EphemeralKey() };
            using var client = new ThreatReportService(config, NullLogger<ThreatReportService>.Instance, httpClient: http);
            Assert.False(client.EvidenceAnchoringConfigured);
            Assert.False(await client.TryReportEvidenceAsync(new EvidenceSummary(), CancellationToken.None));
            config.ReportingProxySharedSecret = config.ProxySharedSecret;
            Assert.False(client.EvidenceAnchoringConfigured);
            Assert.Equal(0, handler.Calls);
            Assert.Equal("NotConfigured", client.AnchorStatus.State);
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task OnlyValidStorageReceiptIsConfirmed_AndPrivateFieldsNeverLeaveClient(bool accepted)
        {
            using var handler = new Handler();
            if (!accepted) handler.Reply = "{\"success\":true}";
            using var http = new HttpClient(handler);
            var config = new ThreatReportingConfig { ReportingProxySharedSecret = EphemeralKey() };
            using var client = new ThreatReportService(config, NullLogger<ThreatReportService>.Instance, httpClient: http);
            bool result = await client.TryReportEvidenceAsync(new EvidenceSummary
            {
                ReportId = "private-host-report", Host = "private-host", ProcessName = "private-process",
                Urls = new[] { "https://private.invalid/user" }, ManifestSha256 = new string('a', 64)
            }, CancellationToken.None);
            Assert.Equal(accepted, result);
            Assert.Equal(accepted ? "Confirmed" : "Failed", client.AnchorStatus.State);
            Assert.DoesNotContain("private", handler.Body);
            Assert.DoesNotContain("Urls", handler.Body);
            Assert.DoesNotContain("Host", handler.Body);
            Assert.Equal(1, handler.Calls);
        }

        [Fact]
        public async Task FailedStorage_IsNotReportedAsAnchored()
        {
            using var handler = new Handler { Status = HttpStatusCode.ServiceUnavailable };
            using var http = new HttpClient(handler);
            using var client = new ThreatReportService(new ThreatReportingConfig { ReportingProxySharedSecret = EphemeralKey() },
                NullLogger<ThreatReportService>.Instance, httpClient: http);
            Assert.False(await client.TryReportEvidenceAsync(new EvidenceSummary { ReportId = "fixture" }, CancellationToken.None));
            Assert.Equal("Failed", client.AnchorStatus.State);
            Assert.Null(client.AnchorStatus.Receipt);
        }
    }
}
