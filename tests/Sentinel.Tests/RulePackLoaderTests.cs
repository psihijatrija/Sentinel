using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;
using Sentinel.Core.Plugins;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for RulePackLoader signature verification (fail-closed) and the pure
    /// FragmentCorrelationRule.Evaluate correlation logic. The embedded RSA public key is a
    /// placeholder, so real signature acceptance cannot be unit-tested here - but the
    /// security-critical REJECT paths (legacy HMAC, missing/garbage signature, empty pack)
    /// and the composite-match logic are fully deterministic.
    /// </summary>
    public class RulePackLoaderSignatureTests : IDisposable
    {
        private readonly string _tempDir;

        public RulePackLoaderSignatureTests()
        {
            _tempDir = Path.Combine(Path.GetTempPath(), "sentinel_rp_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(_tempDir);
        }

        public void Dispose()
        {
            try { Directory.Delete(_tempDir, true); } catch { }
        }

        private RulePackLoader NewLoader(out PluginRegistry registry)
        {
            registry = new PluginRegistry();
            return new RulePackLoader(registry, NullLogger<RulePackLoader>.Instance);
        }

        private string WritePack(string json)
        {
            var path = Path.Combine(_tempDir, "test.pack.json");
            File.WriteAllText(path, json);
            return path;
        }

        // ---------------- fail-closed signature verification ----------------

        [Fact]
        public void TryLoadPack_LegacyHmacPack_IsRejected()
        {
            var loader = NewLoader(out var registry);
            var path = WritePack(@"{ ""name"":""x"", ""rules"":[], ""hmac"":""abc"" }");

            Assert.False(loader.TryLoadPack(path));
            Assert.Empty(registry.CorrelationRules);
        }

        [Fact]
        public void TryLoadPack_MissingSignature_IsRejected()
        {
            var loader = NewLoader(out var registry);
            var path = WritePack(@"{ ""name"":""x"", ""rules"":[{ ""name"":""r"", ""requiredFragments"":[""A""] }] }");

            Assert.False(loader.TryLoadPack(path));
            Assert.Empty(registry.CorrelationRules);
        }

        [Fact]
        public void TryLoadPack_InvalidBase64Signature_IsRejected()
        {
            var loader = NewLoader(out _);
            var path = WritePack(@"{ ""name"":""x"", ""signature"":""!!!not-base64!!!"", ""rules"":[] }");

            Assert.False(loader.TryLoadPack(path));
        }

        [Fact]
        public void TryLoadPack_WellFormedButUntrustedSignature_IsRejected()
        {
            // A syntactically valid base64 signature that was NOT produced by the real private
            // key must fail RSA verification - fail closed, nothing registered.
            var loader = NewLoader(out var registry);
            var fakeSig = Convert.ToBase64String(new byte[256]);
            var path = WritePack(
                $@"{{ ""name"":""x"", ""rules"":[{{ ""name"":""r"", ""requiredFragments"":[""A""] }}], ""signature"":""{fakeSig}"" }}");

            Assert.False(loader.TryLoadPack(path));
            Assert.Empty(registry.CorrelationRules);
        }

        [Fact]
        public void TryLoadPack_NonexistentFile_ReturnsFalse()
        {
            var loader = NewLoader(out _);
            Assert.False(loader.TryLoadPack(Path.Combine(_tempDir, "does_not_exist.pack.json")));
        }

        // ---------------- LoadPackForTest (bypasses signature) ----------------

        [Fact]
        public void LoadPackForTest_RegistersRulesWithFragments()
        {
            var loader = NewLoader(out var registry);
            var pack = new RulePackFile
            {
                Name = "p",
                Rules = new List<RulePackCorrelationRule>
                {
                    new() { Name = "r1", RequiredFragments = new List<string> { "A", "B" } },
                    new() { Name = "r2", RequiredFragments = new List<string> { "C" } },
                }
            };

            var n = loader.LoadPackForTest(pack);

            Assert.Equal(2, n);
            Assert.Equal(2, registry.CorrelationRules.Count);
        }

        [Fact]
        public void LoadPackForTest_SkipsRulesWithNoFragments()
        {
            var loader = NewLoader(out var registry);
            var pack = new RulePackFile
            {
                Name = "p",
                Rules = new List<RulePackCorrelationRule>
                {
                    new() { Name = "ok", RequiredFragments = new List<string> { "A" } },
                    new() { Name = "empty", RequiredFragments = new List<string>() },
                }
            };

            var n = loader.LoadPackForTest(pack);

            Assert.Equal(1, n);
            Assert.Single(registry.CorrelationRules);
        }

        // ---------------- FragmentCorrelationRule.Evaluate (pure logic) ----------------

        private static DetectionEvent Sig(string ruleName) => new() { RuleName = ruleName };

        private static FragmentCorrelationRule Rule(params string[] fragments) =>
            new(new RulePackCorrelationRule
            {
                Name = "composite",
                MinSignals = 2,
                RequiredFragments = new List<string>(fragments),
                Confidence = 0.93,
                Evidence = "cred + c2"
            }, "pack");

        [Fact]
        public void Evaluate_AllFragmentsPresent_FiresComposite()
        {
            var rule = Rule("LSASS", "Beacon");
            var signals = new List<DetectionEvent>
            {
                Sig("LSASS Credential Dump"),
                Sig("C2 Beacon Behavior"),
            };

            var result = rule.Evaluate(1234, "evil.exe", signals);

            Assert.NotNull(result);
            Assert.Equal(ResponseAction.QuarantineAndKill, result!.AuthorizedResponse);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal("true", result.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.Contains("COMPOSITE", result.Evidence);
        }

        [Fact]
        public void Evaluate_MissingOneFragment_DoesNotFire()
        {
            var rule = Rule("LSASS", "Beacon");
            var signals = new List<DetectionEvent>
            {
                Sig("LSASS Credential Dump"),
                Sig("Some Unrelated Rule"),
            };

            Assert.Null(rule.Evaluate(1234, "evil.exe", signals));
        }

        [Fact]
        public void Evaluate_BelowMinSignals_DoesNotFire()
        {
            var rule = Rule("LSASS", "Beacon");
            var signals = new List<DetectionEvent> { Sig("LSASS and Beacon in one") };

            // Only one signal: below the enforced floor of max(2, MinSignals).
            Assert.Null(rule.Evaluate(1234, "evil.exe", signals));
        }

        [Fact]
        public void Evaluate_NullSignals_DoesNotFire()
        {
            var rule = Rule("LSASS", "Beacon");
            Assert.Null(rule.Evaluate(1234, "evil.exe", null!));
        }

        [Fact]
        public void Evaluate_FragmentMatchIsCaseInsensitive()
        {
            var rule = Rule("lsass", "beacon");
            var signals = new List<DetectionEvent>
            {
                Sig("LSASS Credential Dump"),
                Sig("C2 BEACON Behavior"),
            };

            Assert.NotNull(rule.Evaluate(1234, "evil.exe", signals));
        }

        [Fact]
        public void Evaluate_ConfidenceIsClampedIntoBand()
        {
            // Confidence below the 0.85 floor is raised; above 0.97 ceiling is capped.
            var low = new FragmentCorrelationRule(new RulePackCorrelationRule
            {
                Name = "lo", MinSignals = 2, Confidence = 0.10,
                RequiredFragments = new List<string> { "A", "B" }
            }, "pack");
            var signals = new List<DetectionEvent> { Sig("A rule"), Sig("B rule") };

            var r = low.Evaluate(1, "p", signals);
            Assert.NotNull(r);
            Assert.True(r!.Confidence >= 0.85 && r.Confidence <= 0.97);
        }
    }
}
