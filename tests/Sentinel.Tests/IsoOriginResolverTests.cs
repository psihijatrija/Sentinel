using System.IO;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    /// <summary>
    /// Tests for IsoOriginResolver's deterministic, fail-closed paths. The WMI-backed
    /// resolution (ResolveBackingImagePath) needs a mounted image and cannot be unit-tested
    /// here, but every guard, normalization, and null/empty fail-closed branch is deterministic.
    /// IsoOriginResolver is read-only by contract - these tests confirm it never throws and
    /// returns safe defaults on bad input.
    /// </summary>
    public class IsoOriginResolverTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void IsImagePathOnMountedIso_NullOrEmpty_ReturnsFalse(string? path)
        {
            Assert.False(IsoOriginResolver.IsImagePathOnMountedIso(path));
        }

        [Fact]
        public void IsImagePathOnMountedIso_SystemDrivePath_ReturnsFalse()
        {
            // The system drive is a fixed disk, never a CD-ROM/mounted-ISO volume.
            var sys = Path.Combine(Path.GetPathRoot(System.Environment.SystemDirectory)!, "Windows", "explorer.exe");
            Assert.False(IsoOriginResolver.IsImagePathOnMountedIso(sys));
        }

        [Fact]
        public void IsImagePathOnMountedIso_GarbagePath_ReturnsFalse_NoThrow()
        {
            // Unresolvable / malformed path must fail closed, not throw.
            Assert.False(IsoOriginResolver.IsImagePathOnMountedIso("::::not-a-path::::"));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("EE")]      // more than one letter
        [InlineData("1")]       // not a letter
        [InlineData("E:\\sub")] // not a bare drive letter after trimming
        public void EnumerateProcessesRunningFromDrive_InvalidLetter_ReturnsEmpty(string? letter)
        {
            var pids = IsoOriginResolver.EnumerateProcessesRunningFromDrive(letter);
            Assert.NotNull(pids);
            Assert.Empty(pids);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("EE")]
        [InlineData("1")]
        public void ResolveBackingImagePath_InvalidLetter_ReturnsNull(string? letter)
        {
            Assert.Null(IsoOriginResolver.ResolveBackingImagePath(letter));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(4)]
        [InlineData(-1)]
        public void ResolveBackingImageForProcess_SystemPids_ReturnNull(int pid)
        {
            // PIDs <= 4 (System/Idle) are never ISO-hosted; fail closed.
            Assert.Null(IsoOriginResolver.ResolveBackingImageForProcess(pid));
        }

        [Fact]
        public void ResolveBackingImageForProcess_CurrentProcess_ReturnsNull()
        {
            // The test host runs from a fixed disk, so it is not on a mounted ISO - null, no throw.
            var pid = System.Diagnostics.Process.GetCurrentProcess().Id;
            Assert.Null(IsoOriginResolver.ResolveBackingImageForProcess(pid));
        }

        [Theory]
        [InlineData("E")]
        [InlineData("e")]
        [InlineData("E:")]
        [InlineData("E:\\")]
        public void ResolveBackingImagePath_WellFormedLetter_DoesNotThrow(string letter)
        {
            // No mounted image at E: on the test host -> null, but the normalization + WMI
            // fail-closed path must not throw for any well-formed letter spelling.
            var result = IsoOriginResolver.ResolveBackingImagePath(letter);
            Assert.Null(result);
        }
    }
}
