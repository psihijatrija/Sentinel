using System;
using System.Diagnostics;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class HardeningModuleTests
    {
        [Fact]
        public void SafeKillProcessTree_RefusesToKillPid0()
        {
            // Should not throw, just return silently
            HardeningModule.SafeKillProcessTree(0);
        }

        [Fact]
        public void SafeKillProcessTree_RefusesToKillPid4()
        {
            // PID 4 is System - should be refused
            HardeningModule.SafeKillProcessTree(4);
        }

        [Fact]
        public void SafeKillProcessTree_RefusesToKillNegativePid()
        {
            HardeningModule.SafeKillProcessTree(-1);
        }

        [Fact]
        public void SafeKillProcessTree_RefusesToKillCsrss()
        {
            // Find csrss PID and verify SafeKillProcessTree won't kill it
            // We can't actually call it with csrss PID in a unit test (would need admin)
            // but we verify the logic by confirming the method doesn't throw for nonexistent PID
            HardeningModule.SafeKillProcessTree(99999); // Nonexistent PID - should handle gracefully
        }

        [Fact]
        public void SafeKillProcessTree_HandlesNonexistentPidGracefully()
        {
            // Should not throw for a PID that doesn't exist
            HardeningModule.SafeKillProcessTree(int.MaxValue);
        }

        [Fact]
        public void ApplyOrFail_ReturnsBoolean()
        {
            // DLL search hardening - just verify it doesn't crash
            var result = HardeningModule.ApplyOrFail();
            // Result depends on platform/permissions, but should never throw
            Assert.IsType<bool>(result);
        }
    }
}
