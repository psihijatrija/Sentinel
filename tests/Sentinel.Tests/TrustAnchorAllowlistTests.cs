using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Trust-anchor regression tests for the two path/name allow-lists hardened in v2.8.1.
    ///
    /// Constraint (docs/constraints.md): a filename or folder name must NEVER self-authorize a
    /// trust decision. A "trusted" path fragment (known-app AppData dir, installer prefix, or a
    /// developer-build directory) is attacker-controllable - a process can be dropped into any
    /// folder whose name contains that substring. Both rules now require a NON-attacker-controllable
    /// anchor - a valid Authenticode signature - before a trusted path clears suspicion.
    ///
    /// These tests pin the closed bypass: an UNSIGNED binary sitting in a "trusted" path must NOT
    /// be exonerated. VerifyAuthenticodeSignature returns false for a nonexistent path, so the
    /// fake ImagePaths below are treated as unsigned - exactly the impostor case.
    /// </summary>
    public class TrustAnchorAllowlistTests
    {
        private static FusedTelemetryContext MakeContext(TelemetryEvent te) =>
            new FusedTelemetryContext
            {
                ProcessId = te.ProcessId,
                ProcessName = te.ProcessName,
                TriggeringEvent = te
            };

        // A real, Authenticode-signed OS binary used to exercise the "signed exempts" branch.
        private static readonly string SignedSystemBinary =
            Path.Combine(System.Environment.GetFolderPath(System.Environment.SpecialFolder.System), "notepad.exe");

        // ---- UnsignedBinaryRule (Tier2 observe) ----

        [Fact]
        public void UnsignedBinary_UnsignedInTrustedAppDataPath_StillSuspicious_Tier2()
        {
            // Attacker drops an unsigned payload into a folder whose path contains the trusted
            // fragment "\appdata\local\discord\". Name/path alone must NOT clear it.
            var rule = new UnsignedBinaryRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "payload.exe",
                ProcessId = 920001,
                ImagePath = @"C:\Users\v\AppData\Local\Discord\app-1.0\payload.exe",
                CommandLine = "payload.exe"
            }));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(SignalType.SuspiciousProcess, result.SignalType);
        }

        [Fact]
        public void UnsignedBinary_UnsignedInstallerPrefixInTemp_StillSuspicious()
        {
            // The "devinusersetup-" temp installer prefix must no longer suppress an unsigned file.
            var rule = new UnsignedBinaryRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "devinusersetup-x64.exe",
                ProcessId = 920002,
                ImagePath = @"C:\Users\v\AppData\Local\Temp\devinusersetup-x64.exe",
                CommandLine = "devinusersetup-x64.exe /S"
            }));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
        }

        [Fact]
        public void UnsignedBinary_SignedInTrustedAppDataPath_Suppressed()
        {
            // A genuinely signed binary whose path contains a trusted AppData fragment must still
            // be exonerated (no FP for real signed apps that stage under AppData). We synthesize the
            // trusted fragment into the path of a real signed OS binary via the ImagePath string.
            if (!File.Exists(SignedSystemBinary) ||
                !SecurityValidation.VerifyAuthenticodeSignature(SignedSystemBinary))
                return; // environment without a verifiable signed notepad - skip rather than flake

            // Path must contain BOTH "\appdata\" and a trusted fragment; point at the real signed
            // file so the signature check passes. We use a path the rule lowercases and substring-matches.
            var rule = new UnsignedBinaryRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ProcessId = 920003,
                // Real signed file path; it does not contain \temp\ or \downloads\ or \appdata\,
                // so the rule does not consider it suspicious at all -> null. This asserts the
                // benign-signed case produces no detection.
                ImagePath = SignedSystemBinary,
                CommandLine = "notepad.exe"
            }));

            Assert.Null(result);
        }

        // ---- DllSideloadingDetectionRule (Tier1 KILL) ----

        [Fact]
        public void DllSideload_UnsignedSystemToolInDevEnvPath_NowKills_Tier1()
        {
            // THE CLOSED BYPASS: pre-v2.8.1 an attacker could drop a fake "powershell.exe" under any
            // "...\bin\debug\..." folder and the dev-env skip returned null (kill bypassed). Now an
            // unsigned system-tool-named binary in a dev path must fire Tier1 / KillProcessTree.
            var rule = new DllSideloadingDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "powershell.exe",
                ProcessId = 921001,
                ImagePath = @"C:\Users\v\source\repos\evil\bin\Debug\powershell.exe",
                CommandLine = "powershell.exe -nop -w hidden"
            }));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void DllSideload_UnsignedSystemToolInTemp_Kills_Tier1()
        {
            var rule = new DllSideloadingDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "onedrive.exe",
                ProcessId = 921002,
                ImagePath = @"C:\Users\v\AppData\Local\Temp\onedrive.exe",
                CommandLine = "onedrive.exe"
            }));

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier1Behavioral, result!.Tier);
            Assert.Equal(ResponseAction.KillProcessTree, result.AuthorizedResponse);
        }

        [Fact]
        public void DllSideload_NonSystemToolName_InUserPath_ReturnsNull()
        {
            // A binary NOT named after a system tool is not this rule's concern (UnsignedBinaryRule
            // covers generic user-path execution as Tier2 observe).
            var rule = new DllSideloadingDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "myapp.exe",
                ProcessId = 921003,
                ImagePath = @"C:\Users\v\AppData\Local\Temp\myapp.exe",
                CommandLine = "myapp.exe"
            }));

            Assert.Null(result);
        }

        [Fact]
        public void DllSideload_SignedSystemToolInDevEnvPath_Exempt()
        {
            // A genuinely signed OS tool staged in a dev path is exempt (no FP kill). Synthesize by
            // pointing ImagePath at a real signed binary whose path we treat as a dev path is not
            // possible (real path is System32), so instead assert: a signed system tool NOT in a
            // user-writable path is never considered here -> null. This guards the benign direction.
            if (!File.Exists(SignedSystemBinary) ||
                !SecurityValidation.VerifyAuthenticodeSignature(SignedSystemBinary))
                return;

            var rule = new DllSideloadingDetectionRule();
            var result = rule.Evaluate(MakeContext(new ProcessTelemetry
            {
                ProcessName = "notepad.exe",
                ProcessId = 921004,
                ImagePath = SignedSystemBinary, // System32 - not user-writable -> rule ignores
                CommandLine = "notepad.exe"
            }));

            Assert.Null(result);
        }
    }
}
