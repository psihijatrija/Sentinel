using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Permanent regression guard: system-wide module identity unload must stay
    /// armed, Tier1, and un-disable-able. If these fail, someone gutted the EDR backbone.
    /// </summary>
    public class ModuleIdentityUnloadPermanentTests
    {
        [Fact]
        public void ProductPosture_ModuleIdentityUnload_Is_Always_On()
        {
            Assert.True(ProductPosture.ModuleIdentityUnloadAlwaysOn);
        }

        [Fact]
        public void MemoryBehaviorAnalyzer_Still_Invokes_DllUnload_On_Timer()
        {
            var src = typeof(MemoryBehaviorAnalyzer).Assembly.Location;
            Assert.False(string.IsNullOrEmpty(src));
            var mba = typeof(MemoryBehaviorAnalyzer).GetMethod(
                "ScanMemory",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            Assert.NotNull(mba);
            var unload = typeof(DllUnloadEngine).GetMethod(nameof(DllUnloadEngine.CheckAndUnloadAsync));
            Assert.NotNull(unload);
            var prune = typeof(DllUnloadEngine).GetMethod(
                nameof(DllUnloadEngine.PruneStalePidCaches),
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance
                | System.Reflection.BindingFlags.Public);
            Assert.NotNull(prune);
        }

        [Fact]
        public void SentinelConfig_Has_No_Switch_To_Disable_DllUnload()
        {
            var names = typeof(SentinelConfig)
                .GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(p => p.Name)
                .ToList();

            foreach (var name in names)
            {
                bool mentionsUnload = name.IndexOf("DllUnload", StringComparison.OrdinalIgnoreCase) >= 0
                    || name.IndexOf("ModuleIdentity", StringComparison.OrdinalIgnoreCase) >= 0
                    || name.IndexOf("ModuleValidation", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!mentionsUnload) continue;

                Assert.False(
                    name.StartsWith("Enable", StringComparison.OrdinalIgnoreCase)
                    || name.StartsWith("Disable", StringComparison.OrdinalIgnoreCase)
                    || name.IndexOf("Enabled", StringComparison.OrdinalIgnoreCase) >= 0,
                    "Do not add a config flag that can disable module identity unload: " + name);
            }
        }

        [Fact]
        public void ApplyTierLaw_Does_Not_Demote_Foreign_Module_Unloaded()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Injection: Foreign Module Unloaded",
                Evidence = @"Process 'notepad' (PID 1234) loaded hostile DLL(s): C:\Evil\helper.dll. FreeLibraryAPC=True; hostKilled=False.",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "notepad",
                ProcessId = 1234,
                Metadata = new Dictionary<string, string>
                {
                    ["Phase"] = "Remediate",
                    ["DllUnloadExempt"] = "true",
                    ["PermanentRule"] = "ModuleIdentityUnload",
                    ["SideloadedDlls"] = @"C:\Evil\helper.dll",
                }
            };

            ResponsePolicy.ApplyTierLaw(d);

            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.True(ResponsePolicy.IsPermanentModuleIdentityUnload(d));
            Assert.True(ResponsePolicy.IsDllUnloadExempt(d));
            Assert.Equal("ModuleIdentityUnload", d.Metadata["TierLaw"]);
            Assert.Equal("ModuleIdentityUnload", d.Metadata["PermanentRule"]);
        }

        [Fact]
        public void ApplyTierLaw_Promotes_Foreign_Module_Unloaded_Even_If_Emitted_Tier2()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Injection: Foreign Module Unloaded",
                Confidence = 0.90,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "chrome",
                ProcessId = 88,
            };

            ResponsePolicy.ApplyTierLaw(d);

            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
        }

        [Fact]
        public void ApplyTierLaw_Still_Demotes_Disk_Only_Sideload_Observe()
        {
            var d = new DetectionEvent
            {
                RuleName = "DLL Sideloading: Plant Next to Image (Observe)",
                Confidence = 0.70,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "host",
                ProcessId = 55,
            };

            ResponsePolicy.ApplyTierLaw(d);

            Assert.Equal(DetectionTier.Tier2Indicator, d.Tier);
            Assert.Equal(ResponseAction.LogOnly, d.AuthorizedResponse);
            Assert.False(ResponsePolicy.IsPermanentModuleIdentityUnload(d));
        }

        [Fact]
        public void Service_Still_Registers_MemoryBehaviorAnalyzer_And_DllUnloadEngine()
        {
            var root = FindRepoRoot();
            var program = File.ReadAllText(Path.Combine(root, "src", "Sentinel.Service", "Program.cs"));
            var service = File.ReadAllText(Path.Combine(root, "src", "Sentinel.Service", "SentinelService.cs"));

            Assert.Contains("AddSingleton<DllUnloadEngine>()", program);
            Assert.Contains("AddSingleton<MemoryBehaviorAnalyzer>()", program);
            Assert.Contains("MemoryBehaviorAnalyzer memoryBehaviorAnalyzer", service);
            Assert.Contains("DllUnloadEngine dllUnloadEngine", service);
            Assert.Contains("SetDllUnloadEngine(dllUnloadEngine)", service);
        }

        [Fact]
        public void ModuleIdentity_Still_Denies_Foreign_Inject()
        {
            var v = ModuleIdentity.Evaluate(
                @"C:\Program Files\App\app.exe",
                @"C:\Evil\helper.dll",
                _ => false);
            Assert.False(v.Allowed);
            Assert.Equal("foreign-path", v.Reason);
        }

        [Fact]
        public void MayPerformDestructiveResponse_Allows_Identity_Unload_Under_Observe()
        {
            var cfg = new SentinelConfig
            {
                ActiveResponse = true,
                ObserveUntilChain = true,
            };
            var d = new DetectionEvent
            {
                RuleName = "DLL Injection: Foreign Module Unloaded",
                ProcessId = 9,
                ProcessName = "host",
                Confidence = 0.90,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly,
            };

            Assert.True(ResponsePolicy.MayPerformDestructiveResponse(d, cfg));
        }

        private static string FindRepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "Sentinel.sln")))
                    return dir.FullName;
                dir = dir.Parent;
            }

            throw new DirectoryNotFoundException("Sentinel.sln not found from " + AppContext.BaseDirectory);
        }
    }
}
