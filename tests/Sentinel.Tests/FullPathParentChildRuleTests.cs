using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Trust-anchor regression tests for FullPathParentChildRule (SENT-003).
    ///
    /// Constraint (docs/constraints.md): a filename alone must NEVER self-authorize a trust
    /// decision. The rule verifies a suspicious parent->child spawn (e.g. winword.exe -> powershell)
    /// by confirming the PARENT'S REAL image path (from the ancestry cache, captured by the OS at
    /// process creation) lives in a legitimate install location - NOT by trusting the parent name
    /// or the child's command line (both attacker-controlled).
    ///
    /// These tests pin the fail-CLOSED behavior: a masqueraded parent (right name, wrong path) or
    /// an unverifiable parent must be REPORTED, not skipped. The pre-fix code checked the child's
    /// command line and failed OPEN, so the spoofed-parent case - the exact thing the rule exists
    /// to catch - escaped detection.
    /// </summary>
    public class FullPathParentChildRuleTests
    {
        private static FusedTelemetryContext MakeContext(TelemetryEvent te) =>
            new FusedTelemetryContext
            {
                ProcessId = te.ProcessId,
                ProcessName = te.ProcessName,
                TriggeringEvent = te
            };

        // Wires a parent PID's authoritative image path into ResponsePolicy's ancestry cache,
        // then returns telemetry for a child spawned by that parent.
        private static (FullPathParentChildRule rule, FusedTelemetryContext ctx) Arrange(
            int parentPid, string parentName, string? parentImagePath,
            int childPid, string childName, string childCmd)
        {
            var cache = new ProcessAncestryCache();
            if (parentImagePath != null)
                cache.RecordProcessStart(parentPid, 0, parentName, parentImagePath);
            ResponsePolicy.SetAncestryCache(cache);

            var ctx = MakeContext(new ProcessTelemetry
            {
                ProcessName = childName,
                ProcessId = childPid,
                ImagePath = $@"C:\Windows\System32\{childName}",
                CommandLine = childCmd,
                ParentProcessId = parentPid,
                ParentProcessName = parentName
            });
            return (new FullPathParentChildRule(), ctx);
        }

        [Fact]
        public void SpoofedParent_WrongPath_FiresFailClosed_Tier2()
        {
            // winword.exe spawning powershell is suspicious. Here the parent "winword.exe" really
            // lives in C:\Temp\ - a masquerade. Even if the attacker stuffs a legit-looking
            // "\microsoft office\" fragment into the CHILD command line, the rule must not be fooled.
            var (rule, ctx) = Arrange(
                parentPid: 910001, parentName: "winword.exe",
                parentImagePath: @"C:\Temp\winword.exe",
                childPid: 910002, childName: "powershell.exe",
                childCmd: @"powershell -nop -w hidden ""C:\Program Files\Microsoft Office\decoy""");

            var result = rule.Evaluate(ctx);

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.Equal("False", result.Metadata!["ParentPathVerified"]);
            // Spoofed/unknown provenance is scored higher than a verified-legit macro spawn.
            Assert.True(result.Confidence >= 0.85);
        }

        [Fact]
        public void UnverifiableParent_NotInCache_FiresFailClosed()
        {
            // Parent name matches the map but we have NO recorded image path for it. The rule
            // must NOT trust the name - it fails closed and reports.
            var (rule, ctx) = Arrange(
                parentPid: 911001, parentName: "excel.exe",
                parentImagePath: null,        // nothing recorded -> unresolvable
                childPid: 911002, childName: "cmd.exe",
                childCmd: "cmd /c whoami");

            var result = rule.Evaluate(ctx);

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal("False", result.Metadata!["ParentPathVerified"]);
        }

        [Fact]
        public void GenuineOfficeParent_VerifiedPath_FiresTier2_Verified()
        {
            // A real Office install spawning a shell (macro behaviour). Still reported as a Tier2
            // observe leg, but marked path-verified with the lower confidence.
            var (rule, ctx) = Arrange(
                parentPid: 912001, parentName: "winword.exe",
                parentImagePath: @"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                childPid: 912002, childName: "powershell.exe",
                childCmd: "powershell -Command Get-Date");

            var result = rule.Evaluate(ctx);

            Assert.NotNull(result);
            Assert.Equal(DetectionTier.Tier2Indicator, result!.Tier);
            Assert.Equal(ResponseAction.LogOnly, result.AuthorizedResponse);
            Assert.Equal("True", result.Metadata!["ParentPathVerified"]);
        }

        [Fact]
        public void UnrelatedParent_NoMatch_ReturnsNull()
        {
            // A parent not in the suspicious-parent map must never fire this rule.
            var (rule, ctx) = Arrange(
                parentPid: 913001, parentName: "myapp.exe",
                parentImagePath: @"C:\Program Files\MyApp\myapp.exe",
                childPid: 913002, childName: "powershell.exe",
                childCmd: "powershell -Command Get-Date");

            Assert.Null(rule.Evaluate(ctx));
        }

        [Fact]
        public void MatchedParent_NonSuspiciousChild_ReturnsNull()
        {
            // winword.exe spawning a non-shell child is not suspicious for this rule.
            var (rule, ctx) = Arrange(
                parentPid: 914001, parentName: "winword.exe",
                parentImagePath: @"C:\Temp\winword.exe",
                childPid: 914002, childName: "notepad.exe",
                childCmd: @"notepad.exe readme.txt");

            Assert.Null(rule.Evaluate(ctx));
        }
    }
}
