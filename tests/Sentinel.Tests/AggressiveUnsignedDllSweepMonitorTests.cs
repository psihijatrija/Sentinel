using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for the opt-in aggressive unsigned-DLL sweep monitor. These target the pure static
    /// <see cref="AggressiveUnsignedDllSweepMonitor.ShouldSkipPath(string)"/> predicate, which is
    /// filesystem-light and elevation-free (no temp files, no real DLLs required).
    /// </summary>
    public class AggressiveUnsignedDllSweepMonitorTests
    {
        [Theory]
        [InlineData(@"C:\Windows\System32\kernel32.dll")]
        [InlineData(@"C:\Windows\SysWOW64\x.dll")]
        [InlineData(@"C:\Windows\WinSxS\x.dll")]
        [InlineData(@"C:\Program Files\app\x.dll")]
        [InlineData(@"C:\Program Files (x86)\app\x.dll")]
        public void ShouldSkipPath_SystemAndProgramPaths_AreSkipped(string path)
        {
            Assert.True(AggressiveUnsignedDllSweepMonitor.ShouldSkipPath(path),
                $"Expected OS-critical/system path to be skipped: {path}");
        }

        [Fact]
        public void ShouldSkipPath_UserWritableDrop_IsCandidate()
        {
            // A DLL in a user-writable location is NOT skipped - it is a sweep candidate.
            Assert.False(AggressiveUnsignedDllSweepMonitor.ShouldSkipPath(@"C:\Users\x\Downloads\evil.dll"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void ShouldSkipPath_NullOrEmpty_FailsClosed(string? path)
        {
            // Fail closed: an unclassifiable path is skipped (never quarantined).
            Assert.True(AggressiveUnsignedDllSweepMonitor.ShouldSkipPath(path!));
        }
    }
}
