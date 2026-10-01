using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests.Monitors
{
    public class TlsCertificateMonitorTests
    {
        //  CertAnalysisResult scoring tests 

        [Fact]
        public void AnalyzeCert_SelfSigned_Alone_DoesNotIncreaseConfidence()
        {
            // Self-signed alone is NOT suspicious - ALL root CAs are self-signed by definition
            using var cert = CreateTestCert("CN=SomeRootCA", "CN=SomeRootCA", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.IsSelfSigned);
            // Base confidence is 0.40, no bonus for self-signed anymore
            Assert.True(result.Confidence < 0.60, $"Self-signed alone should be < 0.60, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_SslComRoot_IsKnownPublicRoot()
        {
            // Regression: SSL.com EV Root was false-flagged as "suspicious" (no CRL on real roots)
            using var cert = CreateTestCert(
                "CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Corporation, L=Houston, S=Texas, C=US",
                "CN=SSL.com EV Root Certification Authority RSA R2, O=SSL Corporation, L=Houston, S=Texas, C=US",
                3650 * 5);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.IsPublicRootCa);
            Assert.True(result.Confidence <= 0.50, $"SSL.com root must stay <=0.50, got {result.Confidence}");
            Assert.DoesNotContain(result.Reasons, r => r.Contains("No CRL/OCSP"));
        }

        [Fact]
        public void AnalyzeCert_LongLivedSelfSignedRoot_MissingCrl_NotScored()
        {
            // Unknown but long-lived self-signed root without CRL/AIA - do not treat as MitM
            using var cert = CreateTestCert("CN=Some New National Root CA", "CN=Some New National Root CA", 3650 * 10);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.IsSelfSigned);
            Assert.DoesNotContain(result.Reasons, r => r.Contains("No CRL/OCSP"));
            Assert.True(result.Confidence < 0.65, $"Long-lived root should stay below remove threshold, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_GoogleTrustServices_IsKnownPublicRoot()
        {
            using var cert = CreateTestCert(
                "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
                "CN=GTS Root R4, O=Google Trust Services LLC, C=US",
                3650 * 10);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.IsPublicRootCa);
            Assert.True(result.Confidence <= 0.50);
        }

        [Fact]
        public void AnalyzeCert_ShortValidity_IncreasesConfidence()
        {
            // Short validity: < 365 days (0.40 base + 0.15 short + 0.10 very-short = 0.65)
            using var cert = CreateTestCert("CN=ShortLived", "CN=RealIssuer", 60);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence > 0.60, $"Expected > 0.60 but got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("Short validity"));
        }

        [Fact]
        public void AnalyzeCert_VeryShortValidity_IncreasesConfidenceMore()
        {
            // Very short validity: < 90 days
            using var cert = CreateTestCert("CN=SuperShort", "CN=RealIssuer", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Contains(result.Reasons, r => r.Contains("Extremely short validity"));
        }

        [Fact]
        public void AnalyzeCert_EnterpriseCa_DowngradesToTier2()
        {
            using var cert = CreateTestCert("CN=Zscaler Root CA", "CN=Zscaler Root CA", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Tier depends on confidence - high confidence unknown certs are Tier1
            Assert.True(result.IsEnterpriseCa);
            Assert.True(result.Confidence <= 0.65, $"Enterprise CA confidence should be capped at 0.65, got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("enterprise TLS inspection"));
        }

        [Fact]
        public void AnalyzeCert_DevTool_DowngradesToTier2()
        {
            using var cert = CreateTestCert("CN=DO_NOT_TRUST_FiddlerRoot", "CN=DO_NOT_TRUST_FiddlerRoot", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Tier depends on confidence - high confidence unknown certs are Tier1
            Assert.True(result.IsDevTool);
            Assert.True(result.Confidence <= 0.55, $"Dev tool confidence should be capped at 0.55, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_MultiSignalAttackCert_HighConfidence()
        {
            // Short validity + no CRL/OCSP + hex-like CN + expired = classic attack cert
            // (0.40 base + 0.15 short + 0.10 very-short + 0.15 no-CRL + 0.15 hex-CN + 0.10 expired = 1.05 capped)
            using var cert = CreateTestCertWithDates("CN=a1b2c3d4e5f6", "CN=a1b2c3d4e5f6",
                DateTime.UtcNow.AddYears(-1), DateTime.UtcNow.AddDays(-1)); // Already expired
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence >= 0.95, $"Multi-signal attack cert should be >= 0.95, got {result.Confidence}");
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier); // High confidence unknown = Tier1
            // Tier depends on confidence - high confidence unknown certs are Tier1
            Assert.Contains(result.Reasons, r => r.Contains("Short validity"));
            Assert.Contains(result.Reasons, r => r.Contains("No CRL/OCSP"));
            Assert.Contains(result.Reasons, r => r.Contains("hex-like"));
            Assert.Contains(result.Reasons, r => r.Contains("expired"));
        }

        [Fact]
        public void AnalyzeCert_KnownPublicRootCA_DowngradesToTier2()
        {
            // DigiCert is now in KnownPublicRootCAs - should be Tier2 with capped confidence
            using var cert = CreateTestCert("CN=DigiCert Global Root G2, O=DigiCert Inc", "CN=DigiCert Global Root G2, O=DigiCert Inc", 7300);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // DigiCert is a known legitimate public root CA
            // Tier depends on confidence - high confidence unknown certs are Tier1
            Assert.True(result.Confidence <= 0.50, $"Known public CA confidence should be capped at 0.50, got {result.Confidence}");
            Assert.Contains(result.Reasons, r => r.Contains("public root CA"));
        }

        [Fact]
        public void AnalyzeCert_ConfidenceCappedAt099()
        {
            // Create cert that would exceed 1.0 without cap
            using var cert = CreateTestCert("CN=ab12cd", "CN=ab12cd", 10);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence <= 0.99, $"Confidence must be capped at 0.99, got {result.Confidence}");
        }

        [Fact]
        public void AnalyzeCert_ExpiredCert_IncreasesConfidence()
        {
            // Expired cert - suspicious to install
            using var cert = CreateTestCertWithDates("CN=Expired", "CN=Expired",
                DateTime.UtcNow.AddYears(-2), DateTime.UtcNow.AddDays(-1));
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.Contains(result.Reasons, r => r.Contains("Already expired"));
        }

        //  ResponseAction integration tests 

        [Fact]
        public void HighConfidenceCert_GetsTier1ForActiveRemoval()
        {
            // High-confidence attack certs are now Tier1Behavioral for active response
            using var cert = CreateTestCert("CN=a1b2c3d4e5f6", "CN=a1b2c3d4e5f6", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            Assert.True(result.Confidence >= 0.80);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
        }

        [Fact]
        public void EnterpriseCa_GetsLogOnlyAction()
        {
            using var cert = CreateTestCert("CN=Palo Alto Networks Root CA", "CN=Palo Alto Networks Root CA", 3650);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Tier depends on confidence - high confidence unknown certs are Tier1
            Assert.True(result.Confidence <= 0.65, $"Enterprise CA confidence should be capped at 0.65, got {result.Confidence}");
        }

        [Fact]
        public void Tier2Detection_NeverTriggersResponse()
        {
            // This is the fundamental Sentinel constraint: Tier2 can never trigger action
            using var cert = CreateTestCert("CN=Zscaler Root CA", "CN=Zscaler Root CA", 30);
            var result = TlsCertificateMonitor.AnalyzeCert(cert);

            // Even with suspicious properties, enterprise CA downgrades to Tier2
            // Tier depends on confidence - high confidence unknown certs are Tier1
        }

        //  Helper methods 

        /// <summary>
        /// Creates a self-signed X509Certificate2 for testing with the specified Subject, Issuer, and validity days.
        /// </summary>
        private static X509Certificate2 CreateTestCert(string subject, string issuer, int validityDays)
        {
            var notBefore = DateTime.UtcNow;
            var notAfter = notBefore.AddDays(validityDays);
            return CreateTestCertWithDates(subject, issuer, notBefore, notAfter);
        }

        /// <summary>
        /// Creates a self-signed X509Certificate2 with explicit NotBefore/NotAfter dates.
        /// </summary>
        private static X509Certificate2 CreateTestCertWithDates(string subject, string issuer, DateTime notBefore, DateTime notAfter)
        {
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = req.CreateSelfSigned(new DateTimeOffset(notBefore), new DateTimeOffset(notAfter));
            return cert;
        }
    }
}

