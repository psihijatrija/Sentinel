using System;
using System.Linq;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Locks the typed <see cref="TerminalFamily"/> taxonomy against the string-based
    /// classifier in <see cref="ResponsePolicy"/>. These tests are the safety net that
    /// lets rules migrate to typed metadata incrementally: if the typed enum and the
    /// legacy string paths ever drift apart, one of these fails with an obvious name.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class TerminalFamilyConsistencyTests
    {
        public TerminalFamilyConsistencyTests()
        {
            ResponsePolicy.ResetForTests();
        }

        // Every kill-grade family in the legacy string HashSet must map to a typed family
        // that reports IsKillGrade == true, and vice versa. This is the invariant that a
        // mistyped literal used to be able to silently break.
        [Fact]
        public void KillGrade_String_Set_Matches_Typed_KillGrade()
        {
            var typedKillGrade = Enum.GetValues(typeof(TerminalFamily))
                .Cast<TerminalFamily>()
                .Where(TerminalFamilies.IsKillGrade)
                .Select(f => f.ToCanonicalString())
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var stringKillGrade = ResponsePolicy.KillGradeTerminalFamilies
                .OrderBy(s => s, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Assert.Equal(typedKillGrade, stringKillGrade);
        }

        // The two families that are terminal (they seed chains) but must NOT be solo
        // kill-grade: BYOVD and Exfil. Locks that carve-out explicitly.
        [Theory]
        [InlineData(TerminalFamily.Byovd)]
        [InlineData(TerminalFamily.Exfil)]
        public void Byovd_And_Exfil_Are_Not_KillGrade(TerminalFamily family)
        {
            Assert.False(TerminalFamilies.IsKillGrade(family));
            Assert.DoesNotContain(family.ToCanonicalString(), ResponsePolicy.KillGradeTerminalFamilies);
        }

        // Canonical string round-trips through the enum for every family - proves the
        // name table has no typos and FromCanonicalString is the exact inverse.
        [Fact]
        public void Every_Family_Round_Trips_Through_Canonical_String()
        {
            foreach (TerminalFamily family in Enum.GetValues(typeof(TerminalFamily)))
            {
                var name = family.ToCanonicalString();
                Assert.False(string.IsNullOrWhiteSpace(name));
                Assert.Equal(family, TerminalFamilies.FromCanonicalString(name));
                // Case-insensitive parse must also work (matches OrdinalIgnoreCase usage).
                Assert.Equal(family, TerminalFamilies.FromCanonicalString(name.ToLowerInvariant()));
            }
        }

        [Fact]
        public void FromCanonicalString_Unknown_Returns_Null()
        {
            Assert.Null(TerminalFamilies.FromCanonicalString(null));
            Assert.Null(TerminalFamilies.FromCanonicalString(""));
            Assert.Null(TerminalFamilies.FromCanonicalString("NotARealFamily"));
            // "Composite" is a metadata marker, NOT a TerminalFamily.
            Assert.Null(TerminalFamilies.FromCanonicalString("Composite"));
        }

        // The typed classifier and the string classifier must agree on real detections.
        [Theory]
        [InlineData("LSASS Credential Dump", SignalType.CredentialTheft, TerminalFamily.CredentialDump)]
        [InlineData("Token Theft: SYSTEM Token Stolen", SignalType.Generic, TerminalFamily.TokenTheft)]
        [InlineData("Reverse Shell Detected", SignalType.ReverseShell, TerminalFamily.ReverseShell)]
        [InlineData("C2 Beaconing: Statistical Beacon Detected", SignalType.NetworkC2, TerminalFamily.C2Beacon)]
        [InlineData("Evasion: Indirect Syscall / Hell's Gate Pattern Detected", SignalType.AntiTamper, TerminalFamily.Evasion)]
        [InlineData("ThreatIntelInjectionRule", SignalType.ProcessInjection, TerminalFamily.Injection)]
        [InlineData("BYOVD: Vulnerable Driver Loaded", SignalType.Generic, TerminalFamily.Byovd)]
        [InlineData("Data Staging: Bulk Upload Exfiltration", SignalType.Generic, TerminalFamily.Exfil)]
        public void Typed_Classifier_Agrees_With_String_Classifier(
            string rule, SignalType signal, TerminalFamily expected)
        {
            var d = new DetectionEvent
            {
                RuleName = rule,
                SignalType = signal,
                ProcessId = 4321,
                ProcessName = "sample.exe",
                Confidence = 0.90,
            };

            var stringOutcome = ResponsePolicy.ClassifyTerminalOutcome(d);
            var typedOutcome = ResponsePolicy.ClassifyTerminalFamily(d);

            Assert.Equal(expected.ToCanonicalString(), stringOutcome);
            Assert.Equal(expected, typedOutcome);
            // Kill-grade agreement between the typed family and the legacy predicate.
            Assert.Equal(ResponsePolicy.IsKillGradeTerminal(d), TerminalFamilies.IsKillGrade(typedOutcome!.Value));
        }

        [Fact]
        public void Non_Terminal_Detection_Classifies_As_Null_In_Both_Paths()
        {
            var d = new DetectionEvent
            {
                RuleName = "Persistence: New Scheduled Task",
                SignalType = SignalType.Generic,
                ProcessId = 4321,
                ProcessName = "sample.exe",
                Confidence = 0.90,
            };

            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalFamily(d));
        }

        // ---- v2.6 typed Family field ------------------------------------------------

        // An explicitly-declared typed Family is authoritative even when the rule name and
        // SignalType carry NO substring the classifier would recognize.
        [Theory]
        [InlineData(TerminalFamily.CredentialDump)]
        [InlineData(TerminalFamily.C2Beacon)]
        [InlineData(TerminalFamily.Injection)]
        [InlineData(TerminalFamily.WmiPersistence)]
        public void Typed_Family_Is_Authoritative_When_Rule_Name_Is_Opaque(TerminalFamily family)
        {
            var d = new DetectionEvent
            {
                RuleName = "Opaque Rule Name With No Recognizable Fragment",
                SignalType = SignalType.Generic,
                ProcessId = 6001,
                ProcessName = "sample.exe",
                Confidence = 0.90,
                Family = family,
            };

            Assert.Equal(family.ToCanonicalString(), ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Equal(family, ResponsePolicy.ClassifyTerminalFamily(d));
        }

        // SAFETY ORDERING: a typed Family must NOT override the benign-installer-noise
        // demotion. Steam DirectX System32 writes stay non-terminal even if some monitor
        // wrongly tagged them with a kill-grade family.
        [Fact]
        public void Typed_Family_Cannot_Override_Benign_Installer_Noise()
        {
            var d = new DetectionEvent
            {
                RuleName = "System Integrity: Unauthorized Write to System Directory",
                Evidence = @"C:\WINDOWS\System32\d3dx9_43.dll created by dxsetup (PID 0)",
                ProcessId = 0,
                ProcessName = "dxsetup",
                Confidence = 0.92,
                Family = TerminalFamily.CredentialDump, // deliberately wrong / hostile tag
                Metadata = new System.Collections.Generic.Dictionary<string, string>
                {
                    ["FilePath"] = @"C:\WINDOWS\System32\d3dx9_43.dll",
                    ["BenignInstallerNoise"] = "true",
                },
            };

            Assert.True(ResponsePolicy.IsBenignInstallerNoise(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalFamily(d));
        }

        // SAFETY ORDERING: a typed Family must NOT override a WeakObserveSeed demotion.
        [Fact]
        public void Typed_Family_Cannot_Override_WeakObserveSeed()
        {
            var d = new DetectionEvent
            {
                RuleName = "Cast Device Guard: Cast Connection Observed",
                ProcessId = 7001,
                ProcessName = "msedge",
                Confidence = 0.90,
                Family = TerminalFamily.C2Beacon, // deliberately wrong / hostile tag
                Metadata = new System.Collections.Generic.Dictionary<string, string>
                {
                    ["WeakObserveSeed"] = "true",
                },
            };

            Assert.True(ResponsePolicy.IsWeakObserveSeed(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Null(ResponsePolicy.ClassifyTerminalFamily(d));
        }

        // A null Family (every legacy detection) must fall through to the substring path
        // exactly as before - proves backward compatibility.
        [Fact]
        public void Null_Family_Falls_Through_To_Substring_Classifier()
        {
            var d = new DetectionEvent
            {
                RuleName = "LSASS Credential Dump via comsvcs",
                SignalType = SignalType.CredentialTheft,
                ProcessId = 8001,
                ProcessName = "rundll32",
                Confidence = 0.93,
                Family = null,
            };

            Assert.Equal(TerminalFamily.CredentialDump.ToCanonicalString(),
                ResponsePolicy.ClassifyTerminalOutcome(d));
            Assert.Equal(TerminalFamily.CredentialDump, ResponsePolicy.ClassifyTerminalFamily(d));
        }

        // End-to-end: a detection shaped exactly like the MIGRATED LsassDumpCanaryMonitor
        // emits (Family set explicitly) classifies as kill-grade CredentialDump and stays
        // Tier1 through ApplyTierLaw. This proves the typed migration works in the live path,
        // and that classification would survive even a rule-name rename.
        [Fact]
        public void Migrated_Lsass_Detection_Is_KillGrade_CredentialDump_EndToEnd()
        {
            var d = new DetectionEvent
            {
                RuleName = "Credential Theft: LSASS Process Access",
                SignalType = SignalType.LsassAccess,
                Family = TerminalFamily.CredentialDump,
                ProcessId = 9101,
                ProcessName = "rundll32",
                Confidence = 0.92,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
            };

            Assert.Equal(TerminalFamily.CredentialDump, ResponsePolicy.ClassifyTerminalFamily(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));

            ResponsePolicy.ApplyTierLaw(d);
            // v2.9.4: the safety property (kill-grade credential-dump detection stays Tier1
            // through ApplyTierLaw) is asserted here; observe-mode gating removed as a
            // settable mode, so the "needs a second signal under observe" tail is dropped.
            Assert.Equal(DetectionTier.Tier1Behavioral, d.Tier);
        }

        // The migration must survive a hostile rename: if the rule name were changed to
        // something opaque, the typed Family still classifies it correctly.
        [Fact]
        public void Migrated_Detection_Survives_Rule_Name_Rename()
        {
            var d = new DetectionEvent
            {
                RuleName = "Totally Different Name After A Refactor",
                SignalType = SignalType.Generic,       // even if SignalType were also lost
                Family = TerminalFamily.CredentialDump,
                ProcessId = 9102,
                ProcessName = "rundll32",
                Confidence = 0.92,
            };

            Assert.Equal(TerminalFamily.CredentialDump, ResponsePolicy.ClassifyTerminalFamily(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));
        }

        // Migrated C2 monitors (ThreatIntelFeedBlocker, NamedPipeMonitor known-C2,
        // NetworkMonitor classic-port, ProtocolCoverage mesh/webhook, GpuProcessMonitor,
        // V217 decoy-pipe) set Family = C2Beacon. Classification survives a rename.
        [Fact]
        public void Migrated_C2_Detection_Survives_Rule_Name_Rename()
        {
            var d = new DetectionEvent
            {
                RuleName = "Renamed C2 Rule With No Recognizable Fragment",
                SignalType = SignalType.Generic,
                Family = TerminalFamily.C2Beacon,
                ProcessId = 9103,
                ProcessName = "beacon",
                Confidence = 0.92,
            };

            Assert.Equal(TerminalFamily.C2Beacon, ResponsePolicy.ClassifyTerminalFamily(d));
            Assert.True(ResponsePolicy.IsKillGradeTerminal(d));
        }
    }
}
