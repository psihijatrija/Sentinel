using System.Collections.Generic;
using System.Text;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Standing security invariants for Sentinel - the cross-cutting laws that must hold
    /// no matter how individual rules or monitors are refactored. Each test locks ONE
    /// named invariant so that a regression fails with an obvious, self-describing name.
    ///
    /// These are deliberately behavioral (they call the real policy/auth code), not mocks.
    /// If one of these ever goes red, a kill-authority or auth guarantee has been weakened.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class SecurityInvariantsTests
    {
        public SecurityInvariantsTests()
        {
            ResponsePolicy.ResetForTests();
        }

        private static SentinelConfig ObserveConfig() => new()
        {
            ActiveResponse = true,
            ObserveUntilChain = true,
            ChainConfirmMinSignals = 2,
            ChainConfirmWindowSeconds = 300,
            MinTier1Confidence = 0.85,
        };

        // ---------------------------------------------------------------------
        // INVARIANT-001: A demoted (Tier2) detection can never retain a
        // destructive AuthorizedResponse. ApplyTierLaw must strip it to LogOnly.
        // ---------------------------------------------------------------------
        [Theory]
        [InlineData("Ghost Process: Unresolvable PID")]
        [InlineData("PPID Spoofing: Parent PID Mismatch")]
        [InlineData("Persistence: New Scheduled Task")]
        [InlineData("Suspicious Outbound Connection")]
        public void Invariant_Tier2_Demotion_Always_Strips_Destructive_Response(string rule)
        {
            var d = new DetectionEvent
            {
                RuleName = rule,
                ProcessId = 3210,
                ProcessName = "suspect.exe",
                Confidence = 0.99,                       // even at max confidence
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            ResponsePolicy.ApplyTierLaw(d);

            // v2.9.4: the safety property (Tier2 demotion strips destructive response) is the
            // ApplyTierLaw result asserted here; observe-mode gating removed as a settable mode.
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        // ---------------------------------------------------------------------
        // INVARIANT-002: An ML score (soft signal) can never, on its own, make a
        // detection kill-grade. Attaching MlUrlProbability / MlPeRiskScore metadata
        // to an otherwise non-terminal detection must not authorize destruction.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Ml_Score_Alone_Never_Authorizes_Kill()
        {
            var d = new DetectionEvent
            {
                RuleName = "DNS Query: High ML URL Probability",
                SignalType = SignalType.Generic,
                ProcessId = 4455,
                ProcessName = "browser.exe",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string>
                {
                    ["MlUrlProbability"] = "0.999",
                    ["MlPeRiskScore"] = "100",
                }
            };

            ResponsePolicy.ApplyTierLaw(d);

            // Not a kill-grade terminal family - ML metadata must not have promoted it.
            // v2.9.4: the safety property (ML score alone never kill-grade) is enforced by the
            // classification methods below; observe-mode gating was removed as a settable mode.
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.False(ResponsePolicy.IsKillGradeTerminal(d));
            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
        }

        // ---------------------------------------------------------------------
        // INVARIANT-003: A kill-grade terminal family below the confidence floor
        // (MinTier1Confidence, default 0.85) must be demoted to observe.
        // ---------------------------------------------------------------------
        [Theory]
        [InlineData(0.10)]
        [InlineData(0.50)]
        [InlineData(0.84)]
        public void Invariant_KillGrade_Below_Confidence_Floor_Is_Demoted(double conf)
        {
            var d = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 5566,
                ProcessName = "beacon.exe",
                Confidence = conf,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            ResponsePolicy.ApplyTierLaw(d);

            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        // ---------------------------------------------------------------------
        // INVARIANT-004: A single high-confidence kill-grade terminal is correctly
        // classified. v2.9.4: observe-until-chain removed as a settable mode, so the
        // "does not solo-nuke under observe" gate no longer exists; the classification
        // safety properties remain asserted.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Single_KillGrade_Terminal_Is_Classified()
        {
            var d = new DetectionEvent
            {
                RuleName = "C2 Beaconing: Statistical Beacon Detected",
                SignalType = SignalType.NetworkC2,
                ProcessId = 6677,
                ProcessName = "beacon.exe",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            Assert.Equal("C2Beacon", ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-005: A WeakObserveSeed metadata flag marks a signal as weak and
        // non-attack-class, regardless of the rule name or confidence.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_WeakObserveSeed_Flag_Is_NotAttackClass()
        {
            var d = new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader",  // normally attack-class
                ProcessId = 7788,
                ProcessName = "loader.exe",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" },
            };

            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-006: PID <= 4 (System/Idle and kernel) can never be a solo
        // attack-class kill target - protects against killing core OS processes.
        // ---------------------------------------------------------------------
        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        public void Invariant_System_Pids_Never_Solo_AttackClass_Kill(int pid)
        {
            var d = new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader",
                ProcessId = pid,
                ProcessName = "System",
                Confidence = 0.99,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            // v2.9.4: PID<=4 protection is observe-independent; enforced via IsAttackClassTerminal.
            Assert.False(ResponsePolicy.IsAttackClassTerminal(d));
        }

        // v2.9.4: INVARIANT-007 (inline host mutation blocked WHILE OBSERVING) removed -
        // observe-until-chain is no longer a settable mode, so there is no "while observing"
        // state to assert. Inline host mutation is now governed by the armed posture.

        // ---------------------------------------------------------------------
        // INVARIANT-008: The dashboard Referer header is never an authenticator.
        // Any local process can forge it, so it must never grant access.
        // ---------------------------------------------------------------------
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("http://localhost/dashboard")]
        [InlineData("http://127.0.0.1:9999/")]
        [InlineData("https://sentinel.local/")]
        public void Invariant_Referer_Never_Grants_Dashboard_Access(string? referer)
        {
            Assert.False(LoopbackDashboardAuth.RefererGrantsAccess(referer));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-009: Dashboard auth requires a matching bearer token. Missing,
        // wrong, or empty-expected tokens must all fail. Comparison is constant-time.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Dashboard_Auth_Requires_Matching_Bearer_Token()
        {
            const string expected = "correct-horse-battery-staple-0123456789";

            // Correct token authenticates.
            Assert.True(LoopbackDashboardAuth.Authenticate("Bearer " + expected, null, expected));
            // Query-string token also works.
            Assert.True(LoopbackDashboardAuth.Authenticate(null, expected, expected));

            // Wrong token fails.
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer wrong-token-value", null, expected));
            // Missing token fails.
            Assert.False(LoopbackDashboardAuth.Authenticate(null, null, expected));
            // Empty expected token fails closed (never authenticates against an unset secret).
            Assert.False(LoopbackDashboardAuth.Authenticate("Bearer " + expected, null, ""));
            // Length-mismatched token fails.
            Assert.False(LoopbackDashboardAuth.ConstantTimeEquals(expected, expected + "x"));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-010: IPC signature verification rejects tampered, short, and
        // malformed signatures. Only a signature computed with the real token over
        // the exact payload verifies.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Ipc_Signature_Verification_Rejects_Tampered_Sig()
        {
            var token = new byte[32];
            for (int i = 0; i < token.Length; i++) token[i] = (byte)(i + 1);

            long ts = 1_700_000_000;
            string payload = ServiceAgentIpc.BuildAuthPayload(ts, "nonce-abcdef01", "ops", "");
            string goodSig = ServiceAgentIpc.Sign(token, payload);

            // Genuine signature verifies.
            Assert.True(ServiceAgentIpc.Verify(token, payload, goodSig));

            // Tampered signature (flip last hex char) fails.
            char last = goodSig[goodSig.Length - 1];
            char flipped = last == '0' ? '1' : '0';
            string tampered = goodSig.Substring(0, goodSig.Length - 1) + flipped;
            Assert.False(ServiceAgentIpc.Verify(token, payload, tampered));

            // Wrong-length signature fails.
            Assert.False(ServiceAgentIpc.Verify(token, payload, "deadbeef"));
            // Null/empty signature fails.
            Assert.False(ServiceAgentIpc.Verify(token, payload, null));
            Assert.False(ServiceAgentIpc.Verify(token, payload, ""));

            // Signature computed with a different token fails (wrong key).
            var otherToken = new byte[32];
            Assert.False(ServiceAgentIpc.Verify(otherToken, payload, goodSig));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-011: A stale IPC timestamp (outside the freshness window) is
        // rejected - blocks replay of an old, otherwise-valid request.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Ipc_Rejects_Stale_Timestamp()
        {
            long now = System.DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            Assert.True(ServiceAgentIpc.IsTimestampFresh(now));
            Assert.True(ServiceAgentIpc.IsTimestampFresh(now - 30));   // within 60s window
            Assert.False(ServiceAgentIpc.IsTimestampFresh(now - 120)); // stale
            Assert.False(ServiceAgentIpc.IsTimestampFresh(now + 120)); // future skew
        }

        // ---------------------------------------------------------------------
        // INVARIANT-012: SecureCompare is length-safe and value-correct - it never
        // throws on null/mismatched input and only returns true for equal buffers.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_SecureCompare_Is_Null_And_Length_Safe()
        {
            var a = Encoding.ASCII.GetBytes("abcdef");
            var b = Encoding.ASCII.GetBytes("abcdef");
            var c = Encoding.ASCII.GetBytes("abcdeX");
            var shorter = Encoding.ASCII.GetBytes("abc");

            Assert.True(SecurityValidation.SecureCompare(a, b));
            Assert.False(SecurityValidation.SecureCompare(a, c));
            Assert.False(SecurityValidation.SecureCompare(a, shorter));
            Assert.False(SecurityValidation.SecureCompare(null, b));
            Assert.False(SecurityValidation.SecureCompare(a, null));
            Assert.False(SecurityValidation.SecureCompare(null, null));
        }

        // ---------------------------------------------------------------------
        // INVARIANT-013: A multi-signal composite stays kill-grade Tier1 through
        // ApplyTierLaw - independent proof must not be demoted.
        // ---------------------------------------------------------------------
        [Fact]
        public void Invariant_Composite_Stays_KillGrade_Through_TierLaw()
        {
            var d = new DetectionEvent
            {
                RuleName = "Injected C2 Beacon",
                Evidence = "[COMPOSITE] injection + C2 on same PID",
                ProcessId = 8899,
                ProcessName = "evil.exe",
                Confidence = 0.98,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
            };

            ResponsePolicy.ApplyTierLaw(d);

            Assert.True(ResponsePolicy.IsNukeComposite(d));
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.True(d.AuthorizedResponse >= ResponseAction.KillProcessTree);
            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, ObserveConfig()));
        }
    }
}
