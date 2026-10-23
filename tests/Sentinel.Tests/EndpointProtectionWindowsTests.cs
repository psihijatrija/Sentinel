using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    [Collection("ResponsePolicy")]
    public class EndpointProtectionWindowsTests
    {
        private static Process StartOwnedSleeper() => Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -Command \"Start-Sleep -Seconds 120\"",
            UseShellExecute = false, CreateNoWindow = true
        })!;

        [LoaderWindowsFact]
        public async Task CorrelatedVictimResponseVerifiesRealExitAndPreservesUnrelatedProcess()
        {
            ResponsePolicy.ResetForTests();
            using var victim = StartOwnedSleeper();
            using var unrelated = StartOwnedSleeper();
            var directory = Path.Combine(Path.GetTempPath(), "SentinelEndpointTest_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            var logger = new JsonlEventLogger(Path.Combine(directory, "events.jsonl"));
            try
            {
                long created = WindowsProcessTreeOperations.GetCreationTime(victim.Id);
                Assert.True(created > 0);
                // Synthetic inert evidence tests correlation -> policy -> native response.
                // No credentials are accessed and no payload is injected/executed.
                var payload = EtwThreatIntelMonitor.CreatePayloadObservation(victim.Id, "owned-sleeper", victim.MainModule!.FileName,
                    created, new[] { new UnbackedPeScanner.Payload(0x10000, 0x11000, 0x20) }, DateTime.UtcNow);
                var read = new DetectionEvent
                {
                    ProcessId = victim.Id, RuleName = "Sensitive File Access: ETW Credential Store Read",
                    Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                    SignalType = SignalType.Generic, AuthorizedResponse = ResponseAction.LogOnly,
                    Metadata = new Dictionary<string, string>
                    {
                        ["SensitiveFileAccess"] = "true", ["AccessSource"] = "KernelFileRead",
                        ["ProcessCreationTime"] = created.ToString()
                    }
                };
                var response = new AdvancedResponseEngine(new SentinelConfig { ActiveResponse = true },
                    new SentinelMetrics(), logger, new QuarantineManager(directory));
                var correlation = new BehavioralCorrelationEngine();
                ResponseExecutionResult? receipt = null;
                correlation.Initialize(async detection =>
                {
                    Assert.Equal(ResponseAction.KillProcessTree, detection.AuthorizedResponse);
                    receipt = await response.HandleAsync(detection);
                });
                await correlation.RegisterSignalAsync(payload);
                Assert.Null(receipt);
                await correlation.RegisterSignalAsync(read);
                Assert.NotNull(receipt);
                Assert.True(receipt!.HasVerifiedProcessExit(victim.Id), receipt.Reason);
                Assert.True(receipt.VerifiesRequestedAction, receipt.Status.ToString());
                Assert.DoesNotContain(receipt.Effects, effect => effect.Action == "Quarantine");
                Assert.True(victim.WaitForExit(5000));
                Assert.False(unrelated.HasExited);
            }
            finally
            {
                foreach (var owned in new[] { victim, unrelated })
                    if (!owned.HasExited) { owned.Kill(); owned.WaitForExit(5000); }
                await logger.DisposeAsync();
                Directory.Delete(directory, true);
            }
        }

        [LoaderWindowsFact]
        public void NativeRegistryCleanupPreservesChangedAndUnrelatedValues()
        {
            string path = @"Software\Sentinel.Tests\" + Guid.NewGuid().ToString("N");
            using var key = Registry.CurrentUser.CreateSubKey(path);
            try
            {
                const string payload = @"C:\SentinelFixture\payload.exe";
                const string launch = "\"C:\\SentinelFixture\\payload.exe\" --startup";
                key.SetValue("owned", launch, RegistryValueKind.String);
                key.SetValue("unrelated", "\"C:\\Windows\\System32\\notepad.exe\" " + payload, RegistryValueKind.String);
                var store = new RegistryRunValueStore(key);
                var expected = store.Read("owned")!;
                key.SetValue("owned", @"C:\Windows\System32\notepad.exe", RegistryValueKind.String);
                Assert.Equal(ResponseExecutionStatus.Refused, RunKeyCleanup.Remove(store, "owned", expected, new[] { payload }, path).Status);
                Assert.NotNull(store.Read("unrelated"));
                key.SetValue("owned", launch, RegistryValueKind.String);
                Assert.Equal(ResponseExecutionStatus.Verified, RunKeyCleanup.Remove(store, "owned", expected, new[] { payload }, path).Status);
                Assert.Null(store.Read("owned"));
                Assert.NotNull(store.Read("unrelated"));
            }
            finally { Registry.CurrentUser.DeleteSubKeyTree(path, false); }
        }

        [LoaderWindowsFact]
        public void NativeRuntimeProvidersReturnExplicitStatesWithoutRequiringEnabledFeatures()
        {
            var source = new WindowsSecurityAuditSource(NullLogger<WindowsSecurityAuditSource>.Instance);
            var checks = source.ReadRuntimeChecks(CancellationToken.None).ToArray();
            foreach (var name in new[] { ProtectionPosture.CredentialGuard, ProtectionPosture.MemoryIntegrity, ProtectionPosture.LsassProtection })
            {
                var check = Assert.Single(checks, c => c.Name == name);
                Assert.Contains(check.State, new[] { "Unknown", "Unsupported", "ObservedActive", "NeedsReview", "ConfiguredNotRunning", "ContextDependent" });
                Assert.False(string.IsNullOrWhiteSpace(check.Detail));
            }
            Assert.Contains("browser cookies", checks.Single(c => c.Name == ProtectionPosture.CredentialGuard).Detail);
        }
    }
}
