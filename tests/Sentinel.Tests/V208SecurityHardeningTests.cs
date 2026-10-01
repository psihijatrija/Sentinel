using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.1.0 red-team remediation tests: SPKI pinning helpers, proxy nonce auth,
    /// SelfPathGuard plant resistance, ProductInfo version stamp.
    /// </summary>
    public class V209SecurityHardeningTests
    {
        [Fact]
        public void ProductInfo_Version_Is210()
        {
            // v2.6.0: version is computed from the single source of truth (version.txt /
            // stamped assembly version), so assert it tracks that rather than a frozen literal.
            var asmVersion = typeof(ProductInfo).Assembly.GetName().Version?.ToString(3);
            Assert.Equal(asmVersion, ProductInfo.Version);
        }

        [Fact]
        public void ProxyAuth_TryApplyAuthHeaders_IncludesNonceAndTimestamp()
        {
            var config = new ThreatReportingConfig
            {
                ProxySharedSecret = "test-shared-secret-32chars!!!!"
            };
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.test/report/hash");
            Assert.True(ProxyAuthHelper.TryApplyAuthHeaders(request, config, "/report/hash", "{}"));

            Assert.True(request.Headers.Contains("X-Sentinel-Timestamp"));
            Assert.True(request.Headers.Contains("X-Sentinel-Nonce"));
            Assert.True(request.Headers.Contains("X-Sentinel-Signature"));
            Assert.False(request.Headers.Contains("X-Sentinel-Auth"));

            var nonce = request.Headers.GetValues("X-Sentinel-Nonce").First();
            Assert.Equal(32, nonce.Length); // 16 bytes hex
        }

        [Fact]
        public void ProxyAuth_SignaturePayload_IncludesNonce()
        {
            var secret = "test-shared-secret-32chars!!!!";
            var config = new ThreatReportingConfig { ProxySharedSecret = secret };
            var path = "/lookup/vt";
            var body = "{\"type\":\"hash\",\"value\":\"aa\"}";

            using var request = new HttpRequestMessage(HttpMethod.Post, "https://example.test" + path);
            Assert.True(ProxyAuthHelper.TryApplyAuthHeaders(request, config, path, body));

            var ts = request.Headers.GetValues("X-Sentinel-Timestamp").First();
            var nonce = request.Headers.GetValues("X-Sentinel-Nonce").First();
            var sig = request.Headers.GetValues("X-Sentinel-Signature").First();

            var payload = ProxyAuthHelper.BuildSignaturePayload(ts, nonce, path, body);
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var expected = ConvertHex.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            Assert.Equal(expected, sig);

            // Legacy v2.0.4 payload (without nonce) must NOT verify
            var legacy = $"{ts}.{path}.{body}";
            var legacySig = ConvertHex.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(legacy))).ToLowerInvariant();
            Assert.NotEqual(legacySig, sig);
        }

        [Fact]
        public void ProxyAuth_CreateNonce_IsUnique()
        {
            var a = ProxyAuthHelper.CreateNonce();
            var b = ProxyAuthHelper.CreateNonce();
            Assert.NotEqual(a, b);
            Assert.Equal(32, a.Length);
            Assert.Equal(32, b.Length);
        }

        [Fact]
        public void ProxyAuth_EncodeRsaSpki_ProducesValidDerSequence()
        {
            using var rsa = RSA.Create(2048);
            var spki = ProxyAuthHelper.EncodeRsaSubjectPublicKeyInfo(rsa.ExportParameters(false));
            Assert.NotNull(spki);
            Assert.True(spki.Length > 50);
            // DER SEQUENCE tag
            Assert.Equal(0x30, spki[0]);

            // Hash is stable for same key
            using var sha = SHA256.Create();
            var h1 = Convert.ToBase64String(sha.ComputeHash(spki));
            var spki2 = ProxyAuthHelper.EncodeRsaSubjectPublicKeyInfo(rsa.ExportParameters(false));
            var h2 = Convert.ToBase64String(sha.ComputeHash(spki2));
            Assert.Equal(h1, h2);
        }

        [Fact]
        public void ProxyAuth_TryExportSpki_WorksForSelfSignedCert()
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(
                "CN=SentinelPinTest",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

            var spki = ProxyAuthHelper.TryExportSubjectPublicKeyInfo(cert);
            Assert.NotNull(spki);
            Assert.True(spki!.Length > 50);

            var candidates = ProxyAuthHelper.EnumeratePinCandidates(cert).ToList();
            Assert.NotEmpty(candidates);
            // At least SPKI + RawData + GetPublicKey
            Assert.True(candidates.Count >= 2);
        }

        [Fact]
        public void SelfPathGuard_DoesNotTrustArbitraryPeUnderInstall()
        {
            var installDir = AppContext.BaseDirectory;
            var plant = System.IO.Path.Combine(installDir, "planted_malware.exe");
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(plant));
        }

        [Fact]
        public void SelfPathGuard_TrustsOnlyKnownNames()
        {
            var installDir = AppContext.BaseDirectory;
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(
                System.IO.Path.Combine(installDir, "evil.dll")));
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(
                System.IO.Path.Combine(installDir, "Sentinel.Update.exe")));
            // Known name outside install still false
            Assert.False(SelfPathGuard.IsSentinelSelfBinary(@"C:\Temp\Sentinel.Service.exe"));
        }

        [Fact]
        public void HasSharedSecret_StillEnforcesMinLength()
        {
            Assert.False(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig
            {
                ProxySharedSecret = "tooshort"
            }));
            Assert.True(ProxyAuthHelper.HasSharedSecret(new ThreatReportingConfig
            {
                ProxySharedSecret = "0123456789abcdef"
            }));
        }
    }
}
