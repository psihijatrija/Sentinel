using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class CoercionAbusePolicyTests
    {
        [Fact]
        public void RemoteAccessTool_Names_Match_AnyDesk_TeamViewer()
        {
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("AnyDesk"));
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("anydesk.exe"));
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("TeamViewer_Service"));
            Assert.True(CoercionAbusePolicy.IsRemoteAccessToolProcess("rustdesk"));
            Assert.False(CoercionAbusePolicy.IsRemoteAccessToolProcess("notepad"));
            Assert.False(CoercionAbusePolicy.IsRemoteAccessToolProcess("chrome"));
        }

        [Fact]
        public void Surveillance_And_Session_Rules_Classify()
        {
            Assert.True(CoercionAbusePolicy.IsSurveillanceRule(new DetectionEvent
            {
                RuleName = "Screen Capture: DXGI Desktop Duplication"
            }));
            Assert.True(CoercionAbusePolicy.IsSessionTheftRule(new DetectionEvent
            {
                RuleName = "Browser Credential Store Access",
                SignalType = SignalType.CredentialTheft
            }));
            Assert.True(CoercionAbusePolicy.IsRemoteControlRule(new DetectionEvent
            {
                RuleName = "Reverse Shell Detected",
                SignalType = SignalType.ReverseShell
            }));
        }

        [Fact]
        public void IsDigitalCoercionToolkit_Requires_Tag_Or_Composite()
        {
            var plain = new DetectionEvent { RuleName = "C2 Beaconing: Statistical Beacon Detected" };
            Assert.False(CoercionAbusePolicy.IsDigitalCoercionToolkit(plain));

            var composite = new DetectionEvent
            {
                RuleName = "Covert Surveillance + Remote Channel",
                Evidence = "[COMPOSITE] test"
            };
            Assert.True(CoercionAbusePolicy.IsDigitalCoercionToolkit(composite));

            var tagged = new DetectionEvent { RuleName = "Something" };
            CoercionAbusePolicy.TagAsCoercionToolkit(tagged);
            Assert.True(CoercionAbusePolicy.IsDigitalCoercionToolkit(tagged));
        }

        [Fact]
        public async Task Composite_Surveillance_Plus_Network_Fires_Coercion()
        {
            DetectionEvent? emitted = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(e =>
            {
                emitted = e;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Screen Capture: DXGI Desktop Duplication",
                ProcessId = 44001,
                ProcessName = "spy.exe",
                SignalType = SignalType.Generic,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 44001,
                ProcessName = "spy.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(emitted);
            Assert.Equal("Covert Surveillance + Remote Channel", emitted!.RuleName);
            Assert.True(CoercionAbusePolicy.IsDigitalCoercionToolkit(emitted));
            Assert.Equal("true", emitted.Metadata[ResponsePolicy.ChainConfirmedKey]);
            Assert.True(emitted.Confidence >= 0.90);
        }

        [Fact]
        public async Task Composite_SessionTheft_Plus_Exfil_Fires()
        {
            DetectionEvent? emitted = null;
            var engine = new BehavioralCorrelationEngine();
            engine.Initialize(e =>
            {
                emitted = e;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Browser Credential Store Access",
                ProcessId = 44002,
                ProcessName = "stealer.exe",
                SignalType = SignalType.CredentialTheft,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Data Exfiltration: Bulk Upload",
                ProcessId = 44002,
                ProcessName = "stealer.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(emitted);
            // Credential + NetworkC2 may match Credential Dump + Exfiltration first (higher priority)
            Assert.True(
                emitted!.RuleName is "Credential Dump + Exfiltration" or "Session Theft + Abuse Channel",
                $"Unexpected composite: {emitted.RuleName}");
        }

        [Fact]
        public async Task HandleDetectionAsync_CoercionComposite_WritesPackSection()
        {
            var temp = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "sentinel_coercion_" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(temp);
            try
            {
                var cfg = new AutoIncidentReportingConfig
                {
                    Enabled = true,
                    GenerateLocalEvidencePack = true,
                    ReportThreatIntel = false,
                    NotifyUser = false,
                    ReportDirectory = temp,
                    CooldownSeconds = 0,
                    MaxPacksPerHour = 100,
                    MinConfidence = 0.5
                };
                var threat = new ThreatReportService(new ThreatReportingConfig { Enabled = false },
                    NullLogger<ThreatReportService>.Instance);
                var sentinelCfg = new SentinelConfig { SilentObserve = false };
                var reporter = new AutoIncidentReporter(cfg, threat, NullLogger<AutoIncidentReporter>.Instance,
                    sentinelConfig: sentinelCfg);

                var detection = new DetectionEvent
                {
                    RuleName = "Covert Surveillance + Remote Channel",
                    SignalType = SignalType.ProcessInjection,
                    Tier = DetectionTier.Tier1Behavioral,
                    Confidence = 0.94,
                    AuthorizedResponse = ResponseAction.QuarantineAndKill,
                    ProcessName = "implant.exe",
                    ProcessId = 99,
                    Evidence = "[COMPOSITE] surveillance + remote",
                    Reasoning = "test",
                    Metadata = new Dictionary<string, string>
                    {
                        [ResponsePolicy.ChainConfirmedKey] = "true",
                        [CoercionAbusePolicy.AbuseCategoryKey] = CoercionAbusePolicy.AbuseCategoryValue
                    }
                };

                await reporter.HandleDetectionAsync(detection);
                Assert.Equal(1, reporter.PacksGenerated);
                var dirs = System.IO.Directory.GetDirectories(temp);
                Assert.Single(dirs);
                var report = System.IO.File.ReadAllText(System.IO.Path.Combine(dirs[0], "incident_report.txt"));
                Assert.Contains("DIGITAL COERCION", report, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("does not assert", report, StringComparison.OrdinalIgnoreCase);

                var affidavit = System.IO.File.ReadAllText(System.IO.Path.Combine(dirs[0], "victim_affidavit.txt"));
                Assert.Contains("Unauthorized remote control", affidavit, StringComparison.OrdinalIgnoreCase);
            }
            finally
            {
                try { System.IO.Directory.Delete(temp, true); } catch { }
            }
        }
    }
}
