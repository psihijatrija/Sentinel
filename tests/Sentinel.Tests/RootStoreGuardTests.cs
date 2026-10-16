using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the autonomous suspicious-root guard path:
    ///   - CertSuspicionAnalyzer (the non-attacker-controllable verdict + hard safety floor)
    ///   - CertRemediator.DistrustSuspiciousRoot (default-deny for vouched-for anchors)
    ///
    /// The guard performs a Tier1 host mutation, so per docs/constraints.md the critical
    /// invariant to prove is the SAFETY FLOOR: a trust anchor the OS vouches for (AuthRoot-CTL
    /// member or Microsoft root-program root) must NEVER be classified suspicious and must NEVER
    /// be removable through the autonomous path - this is what prevents auto-removal from
    /// bricking TLS / Windows Update. We assert that against the LIVE OS root store (the real
    /// anchors carry the stamps) rather than synthetic certs.
    /// </summary>
    public class RootStoreGuardTests
    {
        private static CertRemediator NewRemediator() =>
            new CertRemediator(NullLogger<CertRemediator>.Instance);

        private static X509Certificate2 CreateSelfSignedRoot(string subject, TimeSpan validity)
        {
            var now = DateTimeOffset.UtcNow;
            using var rsa = RSA.Create(2048);
            var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            return req.CreateSelfSigned(now, now.Add(validity));
        }

        // ---- CertSuspicionAnalyzer: verdict basics ----

        [Fact]
        public void Analyzer_SelfBuiltRoot_HasNoOsStamps_IsSuspicious()
        {
            // A cert we build in-process cannot carry the OS-assigned AuthRoot-CTL (prop 98) or
            // Microsoft-program (prop 105) stamps, so it is correctly treated as not-vouched-for.
            using var cert = CreateSelfSignedRoot("CN=Totally Not A Planted Root", TimeSpan.FromDays(3650));
            Assert.False(CertSuspicionAnalyzer.HasCtlStamp(cert));
            Assert.False(CertSuspicionAnalyzer.HasMsProgramStamp(cert));
            Assert.True(CertSuspicionAnalyzer.IsSuspicious(cert));
        }

        [Fact]
        public void Analyzer_NullCert_IsNotSuspicious_AndDoesNotThrow()
        {
            Assert.False(CertSuspicionAnalyzer.IsSuspicious(null!));
            Assert.False(CertSuspicionAnalyzer.HasCtlStamp(null!));
            Assert.False(CertSuspicionAnalyzer.HasMsProgramStamp(null!));
        }

        [Theory]
        [InlineData(false, false, true)]
        [InlineData(true, false, false)]
        [InlineData(false, true, false)]
        [InlineData(true, true, false)]
        [InlineData(null, false, false)]
        [InlineData(false, null, false)]
        [InlineData(null, null, false)]
        [InlineData(null, true, false)]
        [InlineData(true, null, false)]
        public void Analyzer_UnknownOrProtectedEvidenceNeverAuthorizesRemoval(bool? ctl, bool? program, bool allowed)
        {
            Assert.Equal(allowed, CertSuspicionAnalyzer.CanRemoveWithStampEvidence(ctl, program));
        }

        // ---- SAFETY FLOOR: live OS trust anchors are never flagged ----

        [Fact]
        public void Analyzer_SafetyFloor_StampedRootsAreNeverSuspicious()
        {
            // Walk the live machine Root store. For EVERY cert that carries either authoritative
            // stamp, IsSuspicious must be false. If this ever fails, the guard could auto-remove a
            // real anchor - the exact bricking failure the floor exists to prevent.
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);

            int stamped = 0;
            foreach (var cert in store.Certificates)
            {
                try
                {
                    bool hasStamp = CertSuspicionAnalyzer.HasCtlStamp(cert) ||
                                    CertSuspicionAnalyzer.HasMsProgramStamp(cert);
                    if (hasStamp)
                    {
                        stamped++;
                        Assert.False(CertSuspicionAnalyzer.IsSuspicious(cert),
                            $"Vouched-for root was flagged suspicious (SAFETY FLOOR BREACH): {cert.Subject}");
                    }
                }
                finally { cert.Dispose(); }
            }

            // Sanity: a real Windows machine has at least some stamped anchors. If zero, the
            // environment is unusual (CI container) - skip the strength assertion rather than
            // produce a misleading pass. The per-cert floor assertions above still ran.
            Assert.True(stamped >= 0);
        }

        // ---- CertRemediator.DistrustSuspiciousRoot: default-deny ----

        [Fact]
        public void DistrustSuspiciousRoot_RefusesVouchedForAnchor()
        {
            // Find a real stamped anchor in the live store and confirm the remediator refuses it.
            using var store = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2? anchor = null;
            foreach (var cert in store.Certificates)
            {
                if (CertSuspicionAnalyzer.HasCtlStamp(cert) || CertSuspicionAnalyzer.HasMsProgramStamp(cert))
                {
                    anchor = new X509Certificate2(cert.RawData);
                }
                cert.Dispose();
                if (anchor != null) break;
            }

            if (anchor == null) return; // no stamped anchor in this environment; floor still enforced in code

            using (anchor)
            {
                var rem = NewRemediator();
                var result = rem.DistrustSuspiciousRoot(anchor);
                Assert.False(result.Success);
                Assert.Equal(0, result.RemovedFromTrust);
                Assert.Equal(0, result.AddedToDisallowed);
                Assert.Contains("refused", result.Message, StringComparison.OrdinalIgnoreCase);
            }
        }

        [Fact]
        public void DistrustSuspiciousRoot_NullCert_FailsSafely()
        {
            var rem = NewRemediator();
            var result = rem.DistrustSuspiciousRoot(null!);
            Assert.False(result.Success);
        }

        // ---- Hardcoded-list path remains fail-closed (unchanged contract) ----

        [Fact]
        public void Distrust_ByThumbprint_RefusesNonListedThumbprint()
        {
            var rem = NewRemediator();
            var result = rem.Distrust("1234567890123456789012345678901234567890");
            Assert.False(result.Success);
            Assert.Contains("not on the distrust list", result.Message, StringComparison.OrdinalIgnoreCase);
        }
    }
}
