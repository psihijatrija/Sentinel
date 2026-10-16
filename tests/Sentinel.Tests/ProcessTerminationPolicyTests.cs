using System;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ProcessTerminationPolicyTests
    {
        private static readonly DateTime Now = new(2026, 10, 16, 12, 0, 0, DateTimeKind.Utc);

        [Theory]
        [InlineData("reused")]
        [InlineData("critical")]
        [InlineData("protected")]
        [InlineData("wrong-image")]
        [InlineData("old-evidence")]
        [InlineData("unknown")]
        public void UncertainOrMismatchedIdentityNeverCallsTerminate(string condition)
        {
            using var target = new FakeTarget { CreatedUtc = Now.AddMinutes(-1) };
            target.IsCritical = condition == "critical";
            target.ThrowOnImage = condition == "unknown";
            var expectedStart = condition == "reused" ? Now.AddMinutes(-2) : target.CreatedUtc;
            var expectedImage = condition == "wrong-image" ? "/different.exe" : "/target.exe";
            var evidence = condition == "old-evidence" ? Now.AddMinutes(-2) : Now;
            Assert.False(ProcessTerminationPolicy.TryTerminate(target, evidence, Now,
                _ => condition == "protected", out _, expectedImage, expectedStart));
            Assert.Equal(0, target.TerminationCalls);
        }

        [Theory]
        [InlineData(false, true, false)]
        [InlineData(true, false, false)]
        [InlineData(true, true, true)]
        public void SuccessRequiresBothTerminationAndSameTargetExit(bool terminated, bool exited, bool expected)
        {
            using var target = new FakeTarget { CreatedUtc = Now.AddMinutes(-1), Terminated = terminated, Exited = exited };
            Assert.Equal(expected, ProcessTerminationPolicy.TryTerminate(target, Now, Now, _ => false,
                out _, target.ImagePath, target.CreatedUtc));
            Assert.Equal(1, target.TerminationCalls);
            Assert.Equal(terminated ? 1 : 0, target.ExitChecks);
        }

        private sealed class FakeTarget : IProcessTerminationTarget
        {
            public DateTime CreatedUtc { get; set; }
            public bool IsCritical { get; set; }
            public bool ThrowOnImage { get; set; }
            public string ImagePath => ThrowOnImage ? throw new InvalidOperationException("unreadable fixture") : "/target.exe";
            public bool Terminated { get; set; } = true;
            public bool Exited { get; set; } = true;
            public int TerminationCalls { get; private set; }
            public int ExitChecks { get; private set; }
            public bool Terminate() { TerminationCalls++; return Terminated; }
            public bool WaitForExit(int milliseconds) { ExitChecks++; return Exited; }
            public void Dispose() { }
        }
    }
}
