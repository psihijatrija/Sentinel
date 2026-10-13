using System;
using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class SentinelEventLogWriterTests
    {
        [Fact]
        public void Config_Defaults_CriticalOnly_And_Application_Log()
        {
            var cfg = new WindowsEventLogConfig();
            Assert.True(cfg.Enabled);
            Assert.True(cfg.CriticalOnly);
            Assert.Equal("Application", cfg.LogName);
            Assert.Equal("Sentinel", cfg.SourceName);
            Assert.Equal(30, cfg.MaxWritesPerMinute);
            Assert.True(cfg.HeartbeatEnabled);
        }

        [Fact]
        public void SentinelConfig_Has_WindowsEventLog_Nested()
        {
            var s = new SentinelConfig();
            Assert.NotNull(s.WindowsEventLog);
            Assert.True(s.WindowsEventLog.Enabled);
        }

        [Fact]
        public void Disabled_By_Config_Is_Unavailable_And_Write_Is_NoOp()
        {
            using var writer = new SentinelEventLogWriter(
                new WindowsEventLogConfig { Enabled = false },
                NullLogger<SentinelEventLogWriter>.Instance);

            Assert.False(writer.IsAvailable);
            Assert.Equal("disabled_by_config", writer.DisableReason);

            // Must never throw
            writer.WriteServiceStart("1.9.5");
            writer.WriteChainResponse(new DetectionEvent
            {
                RuleName = "test",
                ProcessName = "x",
                ProcessId = 1,
                Confidence = 0.9
            }, "KILL", "ChainConfirmed nuke");
            writer.WriteEvidencePack(new DetectionEvent { RuleName = "t", ProcessId = 1 }, @"C:\pack");
            writer.WriteHeartbeat("1.9.5", etwActive: false);

            Assert.Equal(0, writer.WritesSucceeded);
        }

        [Fact]
        public void Write_Never_Throws_When_Disabled()
        {
            using var writer = new SentinelEventLogWriter(
                new WindowsEventLogConfig { Enabled = false });

            var ex = Record.Exception(() =>
            {
                for (int i = 0; i < 50; i++)
                    writer.Write(9999, EventLogEntryType.Error, new string('x', 10_000));
            });
            Assert.Null(ex);
        }

        [Fact]
        public void ProbeEventLogInfrastructure_Does_Not_Throw()
        {
            var ex = Record.Exception(() =>
            {
                _ = SentinelEventLogWriter.ProbeEventLogInfrastructureAvailable();
            });
            Assert.Null(ex);
        }

        [Fact]
        public void Enabled_Writer_Either_Available_Or_Permanently_Disabled_Gracefully()
        {
            // On CI / locked-down / stripped images CreateEventSource may fail - both outcomes OK.
            using var writer = new SentinelEventLogWriter(
                new WindowsEventLogConfig
                {
                    Enabled = true,
                    SourceName = "Sentinel.UnitTest." + Guid.NewGuid().ToString("N")[..8],
                    LogName = "Application",
                    CriticalOnly = true,
                    HeartbeatEnabled = false,
                    MaxWritesPerMinute = 60
                },
                NullLogger<SentinelEventLogWriter>.Instance);

            Assert.True(writer.IsAvailable || writer.IsPermanentlyDisabled);

            var ex = Record.Exception(() =>
            {
                writer.WriteServiceStart("1.9.5-test");
                writer.WriteChainResponse(new DetectionEvent
                {
                    RuleName = "Covert Surveillance + Remote Channel",
                    ProcessName = "spy",
                    ProcessId = 42,
                    Confidence = 0.94,
                    Metadata = new System.Collections.Generic.Dictionary<string, string>
                    {
                        [CoercionAbusePolicy.AbuseCategoryKey] = CoercionAbusePolicy.AbuseCategoryValue
                    }
                }, "KILL", "ChainConfirmed nuke (Composite)");
            });
            Assert.Null(ex);
        }

        [Fact]
        public void RateLimit_Drops_Excess_Writes_Without_Throwing()
        {
            using var writer = new SentinelEventLogWriter(
                new WindowsEventLogConfig
                {
                    Enabled = true,
                    SourceName = "Sentinel.UnitTest.Rate." + Guid.NewGuid().ToString("N")[..8],
                    MaxWritesPerMinute = 3,
                    HeartbeatEnabled = false
                },
                NullLogger<SentinelEventLogWriter>.Instance);

            if (!writer.IsAvailable)
            {
                // Stripped host - still a pass for degradation
                Assert.True(writer.IsPermanentlyDisabled);
                return;
            }

            var ex = Record.Exception(() =>
            {
                for (int i = 0; i < 20; i++)
                    writer.WriteServiceStart("rate-test-" + i);
            });
            Assert.Null(ex);
            // At most a few succeeded (budget 3); never storm
            Assert.True(writer.WritesSucceeded <= 5);
        }
    }
}
