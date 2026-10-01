using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v1.7.8 - Reportable-grade policy, integrity seal, victim affidavit.
    /// </summary>
    public class V178FeatureTests
    {
        [Fact]
        public void AutoIncidentReportingConfig_Defaults_ReportableGrade()
        {
            var cfg = new AutoIncidentReportingConfig();
            Assert.True(cfg.ReportableGradeOnly);
            Assert.Equal(0.85, cfg.MinConfidence);
            Assert.Equal(0.80, cfg.KillAuthorizedMinConfidence);
            Assert.True(cfg.IncludeIntegrityManifest);
            Assert.True(cfg.IncludeVictimAffidavit);
            Assert.True(cfg.CreateZipExport);
            Assert.Equal(20, cfg.MaxPacksPerHour);
        }

        [Theory]
        [InlineData(SignalType.Ransomware, 0.90, ResponseAction.KillProcessTree, true)]
        [InlineData(SignalType.CredentialTheft, 0.88, ResponseAction.KillProcess, true)]
        [InlineData(SignalType.NetworkC2, 0.90, ResponseAction.NetworkIsolate, true)]
        [InlineData(SignalType.Generic, 0.99, ResponseAction.LogOnly, false)]
        [InlineData(SignalType.Ransomware, 0.70, ResponseAction.LogOnly, false)]
        [InlineData(SignalType.Generic, 0.82, ResponseAction.KillProcess, true)] // kill + Tier1-ish path via kill floor
        public void ReportableGrade_ShouldReport(SignalType signal, double conf, ResponseAction action, bool expected)
        {
            var reporter = CreateReporter(reportableOnly: true, minConf: 0.85, killFloor: 0.80);
            var tier = action == ResponseAction.LogOnly && conf < 0.85
                ? DetectionTier.Tier2Indicator
                : DetectionTier.Tier1Behavioral;

            // Kill-authorized Generic still needs attack character or Tier1 under grade-only
            var ev = new DetectionEvent
            {
                RuleName = signal == SignalType.Generic ? "Unknown" : "Attack Rule",
                SignalType = signal,
                Tier = DetectionTier.Tier1Behavioral,
                Confidence = conf,
                AuthorizedResponse = action,
                ProcessName = "x.exe",
                ProcessId = 9
            };

            // For generic kill without attack character: Tier1Behavioral + kill allows report
            if (signal == SignalType.Generic && action >= ResponseAction.KillProcess)
            {
                Assert.True(reporter.ShouldReport(ev));
                return;
            }

            Assert.Equal(expected, reporter.ShouldReport(ev));
        }

        [Fact]
        public void ReportableGrade_NetworkIsolate_WithoutAttackCharacter_Rejected()
        {
            var reporter = CreateReporter(reportableOnly: true, minConf: 0.85, killFloor: 0.80);
            var ev = new DetectionEvent
            {
                RuleName = "Benign isolate",
                SignalType = SignalType.Generic,
                Tier = DetectionTier.Tier2Indicator,
                Confidence = 0.95,
                AuthorizedResponse = ResponseAction.NetworkIsolate,
                ProcessName = "app.exe",
                ProcessId = 3
            };
            Assert.False(reporter.ShouldReport(ev));
        }

        [Fact]
        public void LooseMode_StillAcceptsHighConfTier1()
        {
            var reporter = CreateReporter(reportableOnly: false, minConf: 0.75, killFloor: 0.70);
            var ev = new DetectionEvent
            {
                RuleName = "Something",
                SignalType = SignalType.Generic,
                Tier = DetectionTier.Tier1Behavioral,
                Confidence = 0.92,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "x",
                ProcessId = 1
            };
            Assert.True(reporter.ShouldReport(ev));
        }

        [Fact]
        public async Task Pack_IncludesIntegrityAffidavitAndZip()
        {
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_v178_" + Guid.NewGuid().ToString("N"));
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
                    ReportableGradeOnly = true,
                    MinConfidence = 0.85,
                    IncludeIntegrityManifest = true,
                    IncludeVictimAffidavit = true,
                    CreateZipExport = true,
                    CooldownSeconds = 0,
                    MaxPacksPerHour = 100,
                    VictimFullName = "Test User",
                    VictimEmail = "test@example.com"
                };

                var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                    NullLogger<ThreatReportService>.Instance);
                var sentinelCfg = new SentinelConfig { SilentObserve = false, ObserveUntilChain = false };
                var reporter = new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance,
                    sentinelConfig: sentinelCfg);

                var hash = new string('b', 64);
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
                    Reasoning = "ransomware",
                    Metadata = new Dictionary<string, string> { ["SHA256"] = hash }
                };

                await reporter.HandleDetectionAsync(detection);

                var dirs = Directory.GetDirectories(temp);
                Assert.Single(dirs);
                var dir = dirs[0];

                Assert.True(File.Exists(Path.Combine(dir, "incident_report.txt")));
                Assert.True(File.Exists(Path.Combine(dir, "victim_affidavit.txt")));
                Assert.True(File.Exists(Path.Combine(dir, "chain_of_custody.txt")));
                Assert.True(File.Exists(Path.Combine(dir, "MANIFEST.sha256")));
                Assert.True(File.Exists(Path.Combine(dir, "MANIFEST.hmac")));
                Assert.True(File.Exists(Path.Combine(dir, "evidence_manifest.json")));
                Assert.True(File.Exists(Path.Combine(dir, "VERIFY.txt")));

                var affidavit = File.ReadAllText(Path.Combine(dir, "victim_affidavit.txt"));
                Assert.Contains("Test User", affidavit);
                Assert.Contains("test@example.com", affidavit);
                Assert.Contains("SIGNATURE", affidavit);

                var body = File.ReadAllText(Path.Combine(dir, "incident_report.txt"));
                Assert.Contains("REPORTABLE-GRADE", body);
                Assert.Contains("Integrity", body, StringComparison.OrdinalIgnoreCase);

                var result = AutoIncidentReporter.VerifyPackIntegrity(dir);
                Assert.True(result.Ok, result.Message);

                // Affidavit edit must not break seal
                File.AppendAllText(Path.Combine(dir, "victim_affidavit.txt"), "\nI noticed ransomware.\n");
                var result2 = AutoIncidentReporter.VerifyPackIntegrity(dir);
                Assert.True(result2.Ok, result2.Message);

                // Editing sealed report must fail verification
                File.AppendAllText(Path.Combine(dir, "incident_report.txt"), "\ntampered\n");
                var result3 = AutoIncidentReporter.VerifyPackIntegrity(dir);
                Assert.False(result3.Ok);

                var zip = dir + ".zip";
                Assert.True(File.Exists(zip));
                Assert.True(File.Exists(zip + ".sha256"));
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { }
                try
                {
                    foreach (var z in Directory.GetFiles(Path.GetDirectoryName(temp)!, "sentinel_v178_*.zip"))
                        File.Delete(z);
                }
                catch { }
            }
        }

        private static AutoIncidentReporter CreateReporter(bool reportableOnly, double minConf, double killFloor)
        {
            var temp = Path.Combine(Path.GetTempPath(), "sentinel_v178_pol_" + Guid.NewGuid().ToString("N"));
            var cfg = new AutoIncidentReportingConfig
            {
                Enabled = true,
                ReportDirectory = temp,
                ReportThreatIntel = false,
                NotifyUser = false,
                ReportableGradeOnly = reportableOnly,
                MinConfidence = minConf,
                KillAuthorizedMinConfidence = killFloor,
                CooldownSeconds = 0
            };
            var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                NullLogger<ThreatReportService>.Instance);
            return new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance);
        }
    }
}
