using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class LogReliabilityRegressionTests
    {
        [Theory]
        [InlineData(@"\SystemRoot\system32\drivers\nvhda64v.sys", @"D:\Windows\system32\drivers\nvhda64v.sys")]
        [InlineData(@"System32\DriverStore\FileRepository\x\gpu.sys", @"D:\Windows\System32\DriverStore\FileRepository\x\gpu.sys")]
        [InlineData(@"\??\D:\Windows\System32\drivers\x.sys", @"D:\Windows\System32\drivers\x.sys")]
        [InlineData(@"x.sys", @"D:\Windows\System32\drivers\x.sys")]
        public void NativeDriverPaths_ResolveAgainstActualWindowsRoot(string input, string expected)
        {
            var path = DriverPathPolicy.Resolve(input, @"D:\Windows");
            Assert.Equal(expected, path);
            Assert.True(DriverPathPolicy.IsStandard(path, @"D:\Windows"));
        }

        [Theory]
        [InlineData(@"D:\Windows\System32\drivers-evil\x.sys")]
        [InlineData(@"D:\Windows\Temp\x.sys")]
        [InlineData(@"D:\Windows\System32\drivers\..\..\Temp\x.sys")]
        [InlineData(@"\Device\HarddiskVolume3\Windows\System32\drivers\x.sys")]
        public void WritableSiblingAndUnknownDevicePaths_AreNotStandard(string path)
        {
            Assert.False(DriverPathPolicy.IsStandard(DriverPathPolicy.Resolve(path, @"D:\Windows"), @"D:\Windows"));
        }

        [Fact]
        public void CoverageAlerts_CoalesceRepeatedLossButReportChangeAndRecovery()
        {
            var alerts = new EtwCoverageAlertState();
            var time = DateTimeOffset.UtcNow;
            Assert.True(alerts.Observe("loss", time));
            Assert.False(alerts.Observe("loss", time.AddSeconds(3)));
            Assert.True(alerts.Observe("provider access denied", time.AddSeconds(6)));
            Assert.False(alerts.Observe("provider access denied", time.AddMinutes(4)));
            Assert.True(alerts.Observe("provider access denied", time.AddMinutes(6)));
            Assert.False(alerts.Observe(null, time.AddMinutes(7)));
            Assert.True(alerts.IsDegraded);
            Assert.False(alerts.Observe(null, time.AddMinutes(7).AddSeconds(30)));
            Assert.False(alerts.IsDegraded);
            Assert.True(alerts.Observe("provider access denied", time.AddMinutes(8)));
        }

        [Fact]
        public void DiagnosticLogger_PreservesExceptionAsValidJson()
        {
            string dir = Path.Combine(Path.GetTempPath(), "SentinelLogTest-" + Guid.NewGuid());
            try
            {
                string path = Path.Combine(dir, "diagnostic.jsonl");
                using var provider = new DiagnosticFileLoggerProvider(path);
                provider.CreateLogger("ETW").LogError(new InvalidOperationException("The interface is unknown"), "ETW failed {Code}", 5);
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                Assert.Equal("ETW failed 5", document.RootElement.GetProperty("message").GetString());
                Assert.Contains("The interface is unknown", document.RootElement.GetProperty("exception").GetString());
            }
            finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
        }

        [Fact]
        public void DiagnosticLogger_UnwritableSinkAndBrokenFormatter_DoNotEscape()
        {
            string blocker = Path.GetTempFileName();
            try
            {
                using var provider = new DiagnosticFileLoggerProvider(Path.Combine(blocker, "diagnostic.jsonl"));
                var logger = provider.CreateLogger("ETW");
                logger.LogError("Must not throw");
                logger.Log<string>(LogLevel.Error, new EventId(1), "state", null,
                    (_, _) => throw new InvalidOperationException("formatter failed"));
            }
            finally { File.Delete(blocker); }
        }

        [Fact]
        public void DiagnosticLogger_RotatesAndBoundsMessages()
        {
            string dir = Path.Combine(Path.GetTempPath(), "SentinelLogTest-" + Guid.NewGuid());
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, "diagnostic.jsonl");
            try
            {
                using (var stream = File.Create(path)) stream.SetLength(5 * 1024 * 1024);
                using var provider = new DiagnosticFileLoggerProvider(path);
                provider.CreateLogger("test").LogWarning(new string('x', 100000));
                Assert.True(File.Exists(path + ".1"));
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                Assert.Equal(32768, document.RootElement.GetProperty("message").GetString()!.Length);
                Assert.Single(File.ReadLines(path));
            }
            finally { Directory.Delete(dir, true); }
        }
    }
}
