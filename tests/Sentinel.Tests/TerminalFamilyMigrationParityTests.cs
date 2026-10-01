using System.Collections.Generic;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// v2.5.7 - parity / safety guards for the typed terminal-family migration.
    ///
    /// The migration lets a monitor declare its terminal outcome via the typed
    /// <see cref="DetectionEvent.Family"/> field, which <see cref="ResponsePolicy.ClassifyTerminalOutcome"/>
    /// trusts ahead of the legacy substring/SignalType inference. Every tag must preserve
    /// the EXACT classification the emit site produced BEFORE the tag was added, otherwise
    /// the migration silently changes kill authority - the highest-consequence bug class here.
    ///
    /// <see cref="TerminalFamilyConsistencyTests"/> proves the typed path WORKS. These tests
    /// prove each real tagged site's typed result MATCHES its legacy result (byte-for-byte),
    /// and lock the invariants the "trust Family first" ordering silently relies on:
    ///   1. Per-site parity: clearing Family yields the same family via the legacy path.
    ///   2. Family-vs-SignalType agreement: no tagged site's SignalType disagrees with its tag.
    ///   3. Safety demotions still win over any kill-grade tag (weak-seed / benign-noise).
    ///   4. Conditional non-terminal siblings stay null.
    ///
    /// Shapes below mirror the ACTUAL emit sites tagged this migration. When a new site is
    /// tagged, add its shape here so the parity guard covers it.
    /// </summary>
    [Collection("ResponsePolicy")]
    public class TerminalFamilyMigrationParityTests
    {
        public TerminalFamilyMigrationParityTests()
        {
            ResponsePolicy.ResetForTests();
        }

        //  Production emit shapes actually tagged this migration 
        // Each row is (label, DetectionEvent factory, expected terminal family). The
        // factory sets Family exactly as the monitor does; the parity test then also
        // evaluates the same shape with Family cleared.
        public static IEnumerable<object[]> TaggedTerminalShapes()
        {
            // CredentialDump ---------------------------------------------------------
            yield return Row("Rules.LsassAccessRule",
                () => new DetectionEvent
                {
                    RuleName = "Credential Theft: LSASS Process Access",
                    SignalType = SignalType.LsassAccess,
                    Family = TerminalFamily.CredentialDump,
                    ProcessId = 1101, ProcessName = "rundll32", Confidence = 0.90,
                },
                TerminalFamily.CredentialDump);

            yield return Row("Rules.ChromeRemoteDebugging",
                () => new DetectionEvent
                {
                    RuleName = "Credential Theft: Chrome Remote Debugging Port",
                    SignalType = SignalType.CredentialTheft,
                    Family = TerminalFamily.CredentialDump,
                    ProcessId = 1102, ProcessName = "chrome", Confidence = 0.90,
                },
                TerminalFamily.CredentialDump);

            yield return Row("NetworkShareMonitor.SmbLateral",
                () => new DetectionEvent
                {
                    RuleName = "Credential Theft: SMB Admin Share Access",
                    SignalType = SignalType.CredentialTheft,
                    Family = TerminalFamily.CredentialDump,
                    ProcessId = 0, ProcessName = "SYSTEM", Confidence = 0.88,
                },
                TerminalFamily.CredentialDump);

            // ReverseShell -----------------------------------------------------------
            yield return Row("Rules.ClickFixEncoded",
                () => new DetectionEvent
                {
                    RuleName = "CVE Class: ClickFix Encoded PowerShell",
                    SignalType = SignalType.ReverseShell,
                    Family = TerminalFamily.ReverseShell,
                    ProcessId = 1201, ProcessName = "powershell", Confidence = 0.96,
                },
                TerminalFamily.ReverseShell);

            // C2Beacon ---------------------------------------------------------------
            yield return Row("Rules.AttackToolsRule.C2",
                () => new DetectionEvent
                {
                    RuleName = "Attack Tool: Command-and-Control Framework",
                    SignalType = SignalType.NetworkC2,
                    Family = TerminalFamily.C2Beacon,
                    ProcessId = 1301, ProcessName = "beacon", Confidence = 0.90,
                },
                TerminalFamily.C2Beacon);

            yield return Row("Rules.CampaignIoc.MaliciousDomain",
                () => new DetectionEvent
                {
                    RuleName = "ThreatFox Known-Malicious Domain: Confirmed C2",
                    SignalType = SignalType.NetworkC2,
                    Family = TerminalFamily.C2Beacon,
                    ProcessId = 1302, ProcessName = "curl", Confidence = 0.85,
                },
                TerminalFamily.C2Beacon);

            // Injection --------------------------------------------------------------
            yield return Row("EtwThreatIntelMonitor.RemoteInjection",
                () => new DetectionEvent
                {
                    RuleName = "ETW-TI: Remote Memory Injection (ALLOCVM_REMOTE)",
                    SignalType = SignalType.ProcessInjection,
                    Family = TerminalFamily.Injection,
                    ProcessId = 1401, ProcessName = "target", Confidence = 0.95,
                },
                TerminalFamily.Injection);

            // Evasion ----------------------------------------------------------------
            yield return Row("EtwThreatIntelMonitor.UnmappedThread",
                () => new DetectionEvent
                {
                    RuleName = "Evasion: Unmapped Thread Start Address",
                    SignalType = SignalType.AntiTamper,
                    Family = TerminalFamily.Evasion,
                    ProcessId = 1501, ProcessName = "target", Confidence = 0.90,
                },
                TerminalFamily.Evasion);

            yield return Row("CriticalMonitors.HellsGate",
                () => new DetectionEvent
                {
                    RuleName = "Evasion: Indirect Syscall / Hell's Gate Pattern Detected",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.Evasion,
                    ProcessId = 1502, ProcessName = "loader", Confidence = 0.92,
                },
                TerminalFamily.Evasion);

            yield return Row("EtwProviderTamperMonitor.EtwManipulation",
                () => new DetectionEvent
                {
                    RuleName = "Anti-Tamper: ETW/Event Log Manipulation Detected",
                    SignalType = SignalType.AntiTamper,
                    Family = TerminalFamily.Evasion,
                    ProcessId = 1503, ProcessName = "logman", Confidence = 0.88,
                },
                TerminalFamily.Evasion);

            yield return Row("ScriptExecutionMonitor.AmsiBypass",
                () => new DetectionEvent
                {
                    RuleName = "Script: AMSI Bypass Detected (amsi.dll Unloaded)",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.Evasion,
                    ProcessId = 1504, ProcessName = "powershell", Confidence = 0.90,
                },
                TerminalFamily.Evasion);

            // TokenTheft -------------------------------------------------------------
            yield return Row("CoverageExpansion.LpeScaffoldTool",
                () => new DetectionEvent
                {
                    RuleName = "LPE Scaffold: Privilege Escalation Tool",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.TokenTheft,
                    ProcessId = 1601, ProcessName = "GodPotato", Confidence = 0.90,
                },
                TerminalFamily.TokenTheft);

            yield return Row("CveCoverage.KernelExploitLoader",
                () => new DetectionEvent
                {
                    RuleName = "CVE Class: Kernel Exploit Loader",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.TokenTheft,
                    ProcessId = 1602, ProcessName = "AfdEoP", Confidence = 0.90,
                    Metadata = new Dictionary<string, string> { ["CveClass"] = "true" },
                },
                TerminalFamily.TokenTheft);

            yield return Row("FileActivityMonitor.LegacyHiveReparse",
                () => new DetectionEvent
                {
                    RuleName = "LegacyHive: Reparse targeting user hive",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.TokenTheft,
                    ProcessId = 1603, ProcessName = "evil", Confidence = 0.88,
                },
                TerminalFamily.TokenTheft);

            // WmiPersistence ---------------------------------------------------------
            yield return Row("SystemIntegrity.HostileWmiSubscription",
                () => new DetectionEvent
                {
                    RuleName = "WMI Persistence: Hostile Event Subscription",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.WmiPersistence,
                    ProcessId = 1701, ProcessName = "WmiPrvSE.exe", Confidence = 0.92,
                },
                TerminalFamily.WmiPersistence);

            yield return Row("SystemIntegrity.WmiPolicyRewrite",
                () => new DetectionEvent
                {
                    RuleName = "WMI Policy Rewrite: Provider Host Wrote Policies",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.WmiPersistence,
                    ProcessId = 1702, ProcessName = "WmiPrvSE.exe", Confidence = 0.88,
                },
                TerminalFamily.WmiPersistence);

            yield return Row("EtwEventDispatcher.WmiPermanentConsumer",
                () => new DetectionEvent
                {
                    RuleName = "WMI-Activity: Permanent Consumer",
                    SignalType = SignalType.SecurityEvasion,
                    Family = TerminalFamily.WmiPersistence,
                    ProcessId = 1703, ProcessName = "scrcons", Confidence = 0.78,
                },
                TerminalFamily.WmiPersistence);
        }

        // GAP 1 + GAP 2 combined: for every tagged production shape, the typed path and
        // the legacy (Family-cleared) path must classify to the SAME family. This is the
        // byte-for-byte invariant the whole migration rests on - previously verified only
        // by hand-tracing in code review.
        [Theory]
        [MemberData(nameof(TaggedTerminalShapes))]
        public void Tagged_Site_Typed_And_Legacy_Paths_Agree(
            string label, System.Func<DetectionEvent> factory, TerminalFamily expected)
        {
            var typed = factory();
            Assert.True(typed.Family.HasValue, $"{label}: shape must set Family");
            Assert.Equal(expected, typed.Family!.Value);

            // Typed path (Family honored).
            var typedOutcome = ResponsePolicy.ClassifyTerminalOutcome(typed);
            Assert.Equal(expected.ToCanonicalString(), typedOutcome);

            // Legacy path (Family cleared) - must return the SAME family via SignalType/substring.
            var legacy = factory();
            legacy.Family = null;
            var legacyOutcome = ResponsePolicy.ClassifyTerminalOutcome(legacy);

            Assert.Equal(typedOutcome, legacyOutcome);
        }

        // GAP 2 (explicit): for tagged shapes whose SignalType is one the classifier switch
        // maps (LsassAccess/CredentialTheft -> CredentialDump, ReverseShell, NetworkC2 -> C2Beacon),
        // the switch-mapped family MUST equal the typed tag. Guards against a future site that
        // sets, e.g., SignalType.NetworkC2 alongside Family = Exfil, which would silently
        // reclassify because Family is trusted first.
        [Theory]
        [MemberData(nameof(TaggedTerminalShapes))]
        public void Tagged_Site_Family_Agrees_With_SwitchMapped_SignalType(
            string label, System.Func<DetectionEvent> factory, TerminalFamily expected)
        {
            var d = factory();
            var switchFamily = SwitchMappedFamily(d.SignalType);
            if (switchFamily == null)
                return; // SignalType not handled by the switch - substring path, nothing to assert.

            Assert.True(expected == switchFamily.Value,
                $"{label}: tag {expected} disagrees with SignalType-mapped family {switchFamily.Value}");
        }

        // Mirror of the SignalType switch inside ClassifyTerminalOutcome. Kept here so a
        // change to that switch that disagrees with a tag trips this test.
        private static TerminalFamily? SwitchMappedFamily(SignalType signal) => signal switch
        {
            SignalType.LsassAccess => TerminalFamily.CredentialDump,
            SignalType.CredentialTheft => TerminalFamily.CredentialDump,
            SignalType.ReverseShell => TerminalFamily.ReverseShell,
            SignalType.NetworkC2 => TerminalFamily.C2Beacon,
            _ => null,
        };

        // GAP 3: encode the migration doc's "traps" section as executable policy. A
        // kill-grade Family set on a detection that carries WeakObserveSeed=true, or whose
        // rule name matches a WeakChainOnly / PureUxObserve fragment, MUST still be demoted
        // to null. This is the exact promotion the safety ordering exists to prevent, and
        // the reason several sites this migration were deliberately left untagged.
        public static IEnumerable<object[]> WeakOrUxShapesThatMustStayNull()
        {
            yield return new object[]
            {
                "WeakObserveSeed metadata flag",
                new DetectionEvent
                {
                    RuleName = "CVE Class: Installer EoP from Staging",
                    ProcessId = 2101, ProcessName = "msiexec", Confidence = 0.90,
                    Metadata = new Dictionary<string, string> { ["WeakObserveSeed"] = "true" },
                },
            };
            yield return new object[]
            {
                "SeImpersonate weak-chain fragment",
                new DetectionEvent
                {
                    RuleName = "Token Theft: SeImpersonatePrivilege from Suspicious Path",
                    ProcessId = 2102, ProcessName = "portable", Confidence = 0.90,
                },
            };
            yield return new object[]
            {
                "Elevated-from-user-path weak-chain fragment",
                new DetectionEvent
                {
                    RuleName = "Privilege Escalation: Elevated Process from User Path",
                    ProcessId = 2103, ProcessName = "tool", Confidence = 0.90,
                },
            };
            yield return new object[]
            {
                "PureUx cast-device fragment",
                new DetectionEvent
                {
                    RuleName = "Cast Device Guard: Cast Connection Observed",
                    ProcessId = 2104, ProcessName = "msedge", Confidence = 0.90,
                },
            };
        }

        [Theory]
        [MemberData(nameof(WeakOrUxShapesThatMustStayNull))]
        public void KillGrade_Family_Cannot_Promote_A_Weak_Or_Ux_Detection(
            string label, DetectionEvent detection)
        {
            // Sanity: without any tag, these already classify null today.
            Assert.True(ResponsePolicy.ClassifyTerminalOutcome(detection) == null,
                $"{label}: expected null before tagging");

            // Now hostilely tag every kill-grade family - the safety demotion must still win.
            foreach (TerminalFamily fam in System.Enum.GetValues(typeof(TerminalFamily)))
            {
                if (!TerminalFamilies.IsKillGrade(fam)) continue;
                detection.Family = fam;
                Assert.True(ResponsePolicy.ClassifyTerminalOutcome(detection) == null,
                    $"{label}: kill-grade tag {fam} wrongly promoted a weak/UX detection");
                Assert.Null(ResponsePolicy.ClassifyTerminalFamily(detection));
            }
        }

        // GAP 4: the conditional non-terminal SIBLINGS of tagged sites must classify null.
        // These are the branches most likely to silently flip if a rule-name prefix is
        // reused. Each mirrors the untagged branch of a conditional Family tag (the monitor
        // sets Family = null there today).
        public static IEnumerable<object[]> ConditionalNonTerminalSiblings()
        {
            // ScriptExecutionMonitor: systemHost branch - "AMSI Not Loaded" observe.
            yield return new object[]
            {
                "ScriptExecution.AmsiNotLoaded (systemHost)",
                new DetectionEvent
                {
                    RuleName = "Script: AMSI Not Loaded (System PowerShell)",
                    SignalType = SignalType.SecurityEvasion,
                    ProcessId = 3101, ProcessName = "powershell", Confidence = 0.45,
                },
            };
            // SystemIntegrity: non-hostile WMI subscription.
            yield return new object[]
            {
                "SystemIntegrity.NewWmiSubscription (!hostile)",
                new DetectionEvent
                {
                    RuleName = "Persistence: New WMI Event Subscription",
                    SignalType = SignalType.SecurityEvasion,
                    ProcessId = 3102, ProcessName = "WmiPrvSE.exe", Confidence = 0.75,
                },
            };
            // EtwEventDispatcher: temporary consumer (!permanent).
            yield return new object[]
            {
                "EtwEventDispatcher.WmiTemporaryConsumer (!permanent)",
                new DetectionEvent
                {
                    RuleName = "WMI-Activity: Temporary Consumer",
                    SignalType = SignalType.SecurityEvasion,
                    ProcessId = 3103, ProcessName = "wmiprvse", Confidence = 0.55,
                },
            };
            // FileActivityMonitor: cloud reparse branch (!hive) - SecurityEvasion observe.
            yield return new object[]
            {
                "FileActivity.CloudReparse (!hive)",
                new DetectionEvent
                {
                    RuleName = "Cloud Files: Unauthorized placeholder reparse",
                    SignalType = SignalType.SecurityEvasion,
                    ProcessId = 3104, ProcessName = "evil", Confidence = 0.80,
                },
            };
            // CoverageExpansion: elevated-from-staging sibling (Tier2 observe, no fragment).
            yield return new object[]
            {
                "CoverageExpansion.ElevatedFromStaging",
                new DetectionEvent
                {
                    RuleName = "LPE Scaffold: Elevated Process from Staging Path",
                    SignalType = SignalType.SecurityEvasion,
                    ProcessId = 3105, ProcessName = "tool", Confidence = 0.78,
                },
            };
        }

        [Theory]
        [MemberData(nameof(ConditionalNonTerminalSiblings))]
        public void Conditional_NonTerminal_Sibling_Classifies_Null(
            string label, DetectionEvent detection)
        {
            Assert.True(ResponsePolicy.ClassifyTerminalOutcome(detection) == null,
                $"{label}: non-terminal sibling must classify null");
            Assert.Null(ResponsePolicy.ClassifyTerminalFamily(detection));
        }

        private static object[] Row(string label, System.Func<DetectionEvent> factory, TerminalFamily expected)
            => new object[] { label, factory, expected };
    }
}
