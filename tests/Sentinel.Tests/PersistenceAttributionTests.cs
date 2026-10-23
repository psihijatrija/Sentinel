using System;
using System.Collections.Generic;
using Microsoft.Win32;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class PersistenceAttributionTests
    {
        private static RunValueSnapshot Value(string command) => new() { Value = command, Kind = RegistryValueKind.String };
        private static readonly string[] Payload = { @"C:\Bad\payload.exe" };

        [Theory]
        [InlineData(@"C:\Bad\payload.exe --startup", true)]
        [InlineData("\"C:\\Bad\\payload.exe\" --startup", true)]
        [InlineData(@"c:\bad\PAYLOAD.EXE", true)]
        [InlineData("\"C:\\Legit\\viewer.exe\" --note C:\\Bad\\payload.exe", false)]
        [InlineData(@"C:\Windows\System32\cmd.exe /c C:\Bad\payload.exe", false)]
        [InlineData(@"C:\Bad\payload.exe.bak", false)]
        [InlineData(@"C:\Bad\payload.exe2", false)]
        [InlineData(@"%APPDATA%\payload.exe", false)]
        [InlineData(@"C:\Program Files\payload.exe", false)]
        [InlineData(@"C:\Bad\other\..\payload.exe", false)]
        [InlineData(@"\\?\C:\Bad\payload.exe", false)]
        [InlineData("\"C:\\Bad\\payload.exe\"suffix", false)]
        public void OnlyExactLiteralDirectLaunchesMatch(string command, bool expected)
            => Assert.Equal(expected, RunKeyCleanup.Matches(Value(command), Payload));

        [Fact]
        public void WrongValueTypesAndUnverifiedAncestorsDoNotAuthorizeRemoval()
        {
            Assert.False(RunKeyCleanup.Matches(new RunValueSnapshot { Value = 42, Kind = RegistryValueKind.DWord }, Payload));
            var result = new ChainTraceResult();
            result.QuarantinedFiles.Add(new QuarantinedFileInfo { OriginalPath = Payload[0] });
            Assert.Empty(RunKeyCleanup.ConfirmedTargets(result));
            result.AdditionalEffects.Add(new ResponseEffect { Action = "Quarantine", Target = Payload[0], Status = ResponseExecutionStatus.Attempted });
            Assert.Empty(RunKeyCleanup.ConfirmedTargets(result));
            result.AdditionalEffects.Add(new ResponseEffect { Action = "Quarantine", Target = Payload[0], Status = ResponseExecutionStatus.Verified });
            Assert.Equal(Payload, RunKeyCleanup.ConfirmedTargets(result));
        }

        private sealed class Store : IRunValueStore
        {
            internal RunValueSnapshot? Current;
            internal int Deletes;
            internal bool IgnoreDelete;
            internal bool Recreate;
            public RunValueSnapshot? Read(string name) => Current;
            public void Delete(string name) { Deletes++; Current = IgnoreDelete ? Current : Recreate ? Value(@"C:\New\safe.exe") : null; }
        }

        [Theory]
        [InlineData("changed")]
        [InlineData("changed-kind")]
        [InlineData("unrelated")]
        public void ChangedOrUnattributedRunValuesArePreserved(string scenario)
        {
            var expected = Value(Payload[0]);
            var store = new Store { Current = Value(scenario == "changed" ? @"C:\Legit\app.exe" : Payload[0]) };
            if (scenario == "changed-kind") store.Current.Kind = RegistryValueKind.ExpandString;
            if (scenario == "unrelated") expected = Value(@"C:\Legit\app.exe --note C:\Bad\payload.exe");
            var result = RunKeyCleanup.Remove(store, "Autorun", expected, Payload, "fixture");
            Assert.Equal(ResponseExecutionStatus.Refused, result.Status);
            Assert.Equal(0, store.Deletes);
        }

        [Theory]
        [InlineData(false, false, ResponseExecutionStatus.Verified)]
        [InlineData(true, false, ResponseExecutionStatus.Failed)]
        [InlineData(false, true, ResponseExecutionStatus.Failed)]
        public void CleanupRequiresAbsenceOnReadback(bool ignored, bool recreated, ResponseExecutionStatus expected)
        {
            var snapshot = Value(Payload[0]);
            var store = new Store { Current = snapshot, IgnoreDelete = ignored, Recreate = recreated };
            var result = RunKeyCleanup.Remove(store, "Autorun", snapshot, Payload, "fixture");
            Assert.Equal(expected, result.Status);
            Assert.Equal(1, store.Deletes);
        }
    }
}
