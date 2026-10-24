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
    public sealed class EndpointWindowsAdminFactAttribute : FactAttribute
    {
        public EndpointWindowsAdminFactAttribute()
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows))
            { Skip = "Requires a disposable elevated Windows integration runner."; return; }
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            if (!new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
                Skip = "Requires an elevated disposable Windows runner; never elevates the test host.";
        }
    }

    [Collection("ResponsePolicy")]
    public class EndpointProtectionWindowsTests
    {
        private static Process StartOwnedSleeper() => Process.Start(new ProcessStartInfo
        {
            FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe"),
            Arguments = "-NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Start-Sleep -Seconds 120")),
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

        [EndpointWindowsAdminFact]
        public void NativePortBlockPolicyCreatesReadsAndPreservesOwnedRule()
        {
            var spec = new PortBlockSpec(65001, 6, 1);
            try
            {
                var applied = WindowsPortBlockPolicy.Inspect(new[] { spec }, apply: true);
                Assert.Contains("Owned port-rule mismatches=0", applied.Detail);
                var read = WindowsPortBlockPolicy.Inspect(new[] { spec }, apply: false);
                Assert.Contains("Owned port-rule mismatches=0", read.Detail);
                // Firewall profile/GPO state is disclosed; this is not a packet-drop test.
            }
            finally { HardeningModule.RemoveFirewallRuleByName(spec.Name); }
        }

        [EndpointWindowsAdminFact]
        public async Task NativeEtwFiltersRetainProcessStartsAndDiscloseProviderAccess()
        {
            using var session = new UnifiedEtwSession(NullLogger<UnifiedEtwSession>.Instance);
            int starts = 0;
            session.RegisterHandler(UnifiedEtwSession.Providers.KernelProcess, evt =>
            { if (evt.EventId == 1) Interlocked.Increment(ref starts); });
            try
            {
                await session.StartAsync(CancellationToken.None);
                Assert.True(session.IsActive);
                using var child = Process.Start(new ProcessStartInfo
                {
                    FileName = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "whoami.exe"),
                    UseShellExecute = false, CreateNoWindow = true
                })!;
                Assert.True(child.WaitForExit(5000));
                for (int i = 0; i < 20 && Volatile.Read(ref starts) == 0; i++) await Task.Delay(250);
                Assert.True(Volatile.Read(ref starts) > 0, "Filtered process-start delivery was not observed.");
                var health = session.QueryHealth();
                Assert.True(health.QuerySucceeded);
                foreach (var provider in new[] { UnifiedEtwSession.Providers.KernelProcess, UnifiedEtwSession.Providers.KernelFile })
                {
                    Assert.Equal(0U, health.ProviderStatus[provider.ToString()]);
                    Assert.Equal(0U, health.ProviderFilterStatus[provider.ToString()]);
                }
                Assert.True(health.ProviderStatus.ContainsKey(UnifiedEtwSession.Providers.ThreatIntelligence.ToString()));
            }
            finally { await session.StopAsync(); }
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
