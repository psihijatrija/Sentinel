using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.7.7 - Auto incident reporting, LE portal directory, indicator extraction.
    /// </summary>
    public class V177FeatureTests
    {
        [Fact]
        public void AutoIncidentReportingConfig_Defaults_AggressiveButGated()
        {
            var cfg = new AutoIncidentReportingConfig();
            Assert.True(cfg.Enabled);
            Assert.True(cfg.GenerateLocalEvidencePack);
            Assert.True(cfg.ReportThreatIntel);
            Assert.True(cfg.NotifyUser);
            Assert.True(cfg.IncludeKillAuthorized);
            Assert.True(cfg.IncludeNetworkIsolate);
            Assert.True(cfg.ReportableGradeOnly);
            Assert.Equal(0.85, cfg.MinConfidence);
            Assert.Equal(0.80, cfg.KillAuthorizedMinConfidence);
            Assert.Equal(300, cfg.CooldownSeconds);
            Assert.Equal(20, cfg.MaxPacksPerHour);
            Assert.Null(cfg.CountryCode);
        }

        [Theory]
        [InlineData(SignalType.Ransomware, DetectionTier.Tier1Behavioral, 0.90, ResponseAction.KillProcessTree, true)]
        [InlineData(SignalType.CredentialTheft, DetectionTier.Tier1Behavioral, 0.88, ResponseAction.KillProcess, true)]
        [InlineData(SignalType.NetworkC2, DetectionTier.Tier1Behavioral, 0.90, ResponseAction.NetworkIsolate, true)]
        [InlineData(SignalType.ProcessInjection, DetectionTier.Tier1Behavioral, 0.88, ResponseAction.KillProcessTree, true)]
        [InlineData(SignalType.Generic, DetectionTier.Tier2Indicator, 0.40, ResponseAction.LogOnly, false)]
        [InlineData(SignalType.Generic, DetectionTier.Tier2Indicator, 0.99, ResponseAction.LogOnly, false)]
        public void ShouldReport_AttackSignals_AndNotNoise(
            SignalType signal, DetectionTier tier, double conf, ResponseAction action, bool expected)
        {
            var reporter = CreateReporter(out _, out _);
            var ev = new DetectionEvent
            {
                RuleName = "Test Rule",
                SignalType = signal,
                Tier = tier,
                Confidence = conf,
                AuthorizedResponse = action,
                ProcessName = "evil.exe",
                ProcessId = 4242,
                Evidence = "test",
                Reasoning = "test"
            };
            Assert.Equal(expected, reporter.ShouldReport(ev));
        }

        [Fact]
        public void ShouldReport_KillAuthorized_EvenGenericSignal()
        {
            var reporter = CreateReporter(out _, out _);
            var ev = new DetectionEvent
            {
                RuleName = "Verdict Gate Malicious",
                SignalType = SignalType.SuspiciousProcess,
                Tier = DetectionTier.Tier1Behavioral,
                Confidence = 0.82,
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                ProcessName = "payload.exe",
                ProcessId = 100
            };
            Assert.True(reporter.ShouldReport(ev));
        }

        [Theory]
        [InlineData("Ransomware Shadow Copy Deletion", true)]
        [InlineData("Application Integrity: Cuckoo Egg Detected", true)]
        [InlineData("LSASS Credential Dump", true)]
        [InlineData("Benign Disk Cleanup", false)]
        [InlineData("Clipboard change rate", false)]
        public void RuleNameLooksLikeAttack_Keywords(string rule, bool expected)
        {
            Assert.Equal(expected, AutoIncidentReporter.RuleNameLooksLikeAttack(rule));
        }

        [Fact]
        public void ExtractIndicators_FromMetadataAndEvidence()
        {
            var hash = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
            var ev = new DetectionEvent
            {
                RuleName = "C2 Beacon",
                Evidence = $"Remote peer 203.0.113.50 connected; hash {hash}",
                Metadata = new Dictionary<string, string>
                {
                    ["SHA256"] = hash,
                    ["RemoteAddress"] = "198.51.100.10",
                    ["C2Url"] = "https://evil.example/payload"
                }
            };

            var set = AutoIncidentReporter.ExtractIndicators(ev);
            Assert.Contains(hash, set.Hashes);
            Assert.Contains("203.0.113.50", set.Ips);
            Assert.Contains("198.51.100.10", set.Ips);
            Assert.Contains("https://evil.example/payload", set.Urls);
        }

        [Fact]
        public void LawEnforcementPortals_ResolvesKnownCountries()
        {
            var us = LawEnforcementPortals.Resolve("US");
            Assert.Equal("US", us.CountryCode);
            Assert.Contains("ic3.gov", us.PrimaryPortalUrl, StringComparison.OrdinalIgnoreCase);

            var hr = LawEnforcementPortals.Resolve("HR");
            Assert.Equal("HR", hr.CountryCode);
            Assert.Contains("mup", hr.PrimaryPortalUrl, StringComparison.OrdinalIgnoreCase);

            var uk = LawEnforcementPortals.Resolve("UK");
            Assert.Contains("actionfraud", uk.PrimaryPortalUrl, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void LawEnforcementPortals_UnknownFallsBackToEuropolDirectory()
        {
            var entry = LawEnforcementPortals.Resolve("ZZ");
            Assert.Equal(LawEnforcementPortals.EuropolDirectory.PrimaryPortalUrl, entry.PrimaryPortalUrl);
        }

        [Fact]
        public void LawEnforcementPortals_InterpolIsInfoOnly()
        {
            Assert.Contains("cannot report", LawEnforcementPortals.InterpolInfo.Notes, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task HandleDetectionAsync_WritesEvidencePack()
        {
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_auto_ir_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                var cfg = new AutoIncidentReportingConfig
                {
                    Enabled = true,
                    GenerateLocalEvidencePack = true,
                    ReportThreatIntel = false,
                    NotifyUser = false,
                    ReportDirectory = temp,
                    CountryCode = "US",
                    CooldownSeconds = 0,
                    MaxPacksPerHour = 100,
                    MinConfidence = 0.5
                };

                var threatCfg = new ThreatReportingConfig { Enabled = false };
                var threat = new ThreatReportService(threatCfg, NullLogger<ThreatReportService>.Instance);
                // SilentObserve default blocks packs until chain-confirmed - disable for pack-path unit test
                var sentinelCfg = new SentinelConfig { SilentObserve = false, ObserveUntilChain = false };
                var reporter = new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance,
                    sentinelConfig: sentinelCfg);

                var hash = new string('a', 64);
                var detection = new DetectionEvent
                {
                    RuleName = "Ransomware Shadow Copy Deletion",
                    SignalType = SignalType.Ransomware,
                    Tier = DetectionTier.Tier1Behavioral,
                    Confidence = 0.95,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessName = "evil.exe",
                    ProcessId = 1,
                    Evidence = "vssadmin delete shadows",
                    Reasoning = "Shadow copy destruction",
                    Metadata = new Dictionary<string, string> { ["SHA256"] = hash }
                };

                var incident = new Incident
                {
                    Id = "INC-000001",
                    Severity = IncidentSeverity.Critical,
                    PrimaryProcessName = "evil.exe"
                };
                incident.Detections.Add(new IncidentDetection
                {
                    DetectionEvent = detection,
                    ReceivedAt = DateTimeOffset.UtcNow
                });

                await reporter.HandleDetectionAsync(detection, incident);

                Assert.Equal(1, reporter.PacksGenerated);
                var dirs = Directory.GetDirectories(temp);
                Assert.Single(dirs);
                Assert.True(File.Exists(Path.Combine(dirs[0], "incident_report.txt")));
                Assert.True(File.Exists(Path.Combine(dirs[0], "indicators.txt")));

                var body = File.ReadAllText(Path.Combine(dirs[0], "incident_report.txt"));
                Assert.Contains("REPORTABLE-GRADE EVIDENCE PACK", body);
                Assert.Contains("ic3.gov", body, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("INTERPOL", body, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("cannot", body, StringComparison.OrdinalIgnoreCase);
                Assert.Contains(hash, body);

                var indicators = File.ReadAllText(Path.Combine(dirs[0], "indicators.txt"));
                Assert.Contains($"sha256={hash}", indicators);
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { /* best effort */ }
            }
        }

        [Fact]
        public async Task HandleDetectionAsync_Disabled_WritesNothing()
        {
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_auto_ir_off_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                var cfg = new AutoIncidentReportingConfig
                {
                    Enabled = false,
                    ReportDirectory = temp
                };
                var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                    NullLogger<ThreatReportService>.Instance);
                var reporter = new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance);

                await reporter.HandleDetectionAsync(new DetectionEvent
                {
                    RuleName = "Ransomware",
                    SignalType = SignalType.Ransomware,
                    Tier = DetectionTier.Tier1Behavioral,
                    Confidence = 0.99,
                    AuthorizedResponse = ResponseAction.KillProcessTree,
                    ProcessId = 5,
                    ProcessName = "x"
                });

                Assert.Equal(0, reporter.PacksGenerated);
                Assert.Empty(Directory.GetDirectories(temp));
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { }
            }
        }

        [Fact]
        public async Task HandleDetectionAsync_ChainConfirmed_WritesPack_Even_LowConfidence_SilentObserve()
        {
            // v1.9.3 regression: chain nukes must produce packs even when the *seed* rule
            // had low confidence / KillAuthorized=false before response promotion.
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_auto_ir_chain_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);
            try
            {
                var cfg = new AutoIncidentReportingConfig
                {
                    Enabled = true,
                    GenerateLocalEvidencePack = true,
                    ReportThreatIntel = false,
                    NotifyUser = false,
                    ReportableGradeOnly = true,
                    MinConfidence = 0.85,
                    KillAuthorizedMinConfidence = 0.80,
                    IncludeKillAuthorized = true,
                    ReportDirectory = temp,
                    CountryCode = "HR",
                    CooldownSeconds = 0,
                    MaxPacksPerHour = 100,
                };
                var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                    NullLogger<ThreatReportService>.Instance);
                var sentinelCfg = new SentinelConfig
                {
                    SilentObserve = true,
                    ObserveUntilChain = true,
                    ActiveResponse = true,
                };
                var reporter = new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance,
                    sentinelConfig: sentinelCfg);

                var detection = new DetectionEvent
                {
                    RuleName = "Threat Intel: Remote Memory Injection",
                    SignalType = SignalType.ProcessInjection,
                    Tier = DetectionTier.Tier1Behavioral,
                    Confidence = 0.55, // below MinConfidence - previously blocked packs
                    AuthorizedResponse = ResponseAction.QuarantineAndKill,
                    ProcessName = "evil.exe",
                    ProcessId = 4242,
                    Evidence = "injection + C2 chain confirmed",
                    Reasoning = "Multi-signal chain to C2Beacon",
                    Metadata = new Dictionary<string, string>
                    {
                        [ResponsePolicy.ChainConfirmedKey] = "true",
                        [ResponsePolicy.TerminalOutcomeKey] = "C2Beacon",
                    }
                };

                Assert.True(AutoIncidentReporter.IsChainConfirmedOrComposite(detection));
                Assert.True(ResponsePolicy.ShouldAutoReportIncident(detection, sentinelCfg));

                await reporter.HandleDetectionAsync(detection);

                Assert.Equal(1, reporter.PacksGenerated);
                Assert.Single(Directory.GetDirectories(temp));
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { /* best effort */ }
            }
        }

        private static AutoIncidentReporter CreateReporter(out string tempDir, out AutoIncidentReportingConfig cfg)
        {
            tempDir = Path.Combine(Path.GetTempPath(), "sentinel_auto_ir_unit_" + Guid.NewGuid().ToString("N"));
            cfg = new AutoIncidentReportingConfig
            {
                Enabled = true,
                ReportDirectory = tempDir,
                ReportThreatIntel = false,
                NotifyUser = false,
                CooldownSeconds = 0
            };
            var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                NullLogger<ThreatReportService>.Instance);
            return new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance);
        }
    }
}
