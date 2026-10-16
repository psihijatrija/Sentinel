using System.Diagnostics;
using System;
using System.Reflection;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ProcessAncestryCacheTests
    {
        [Fact]
        public void ConcurrentStartsDoNotLoseSiblingEntries()
        {
            using var cache = new ProcessAncestryCache();
            System.Threading.Tasks.Parallel.For(0, 100, i =>
                cache.RecordProcessStart(int.MaxValue - i, 0, "fixture-" + i, @"C:\fixture.exe"));
            for (int i = 0; i < 100; i++)
                Assert.Equal("fixture-" + i, cache.GetProcessInfo(int.MaxValue - i).name);
        }

        [Fact]
        public void ChangedGenerationWithdrawsOldParentAuthority()
        {
            using var cache = new ProcessAncestryCache();
            int pid = Process.GetCurrentProcess().Id;
            const int oldParent = int.MaxValue - 1;
            cache.RecordProcessStart(pid, oldParent, "fixture", SecurityValidation.GetProcessImagePath(pid)!);
            var starts = (System.Collections.Generic.Dictionary<int, DateTime>)typeof(ProcessAncestryCache)
                .GetField("_processStarts", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(cache)!;
            var gate = typeof(ProcessAncestryCache).GetField("_cacheGate", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(cache)!;
            lock (gate)
            {
                starts[pid] = DateTime.UtcNow.AddYears(-10); // Simulate retained identity from an earlier PID generation.
                typeof(ProcessAncestryCache).GetMethod("RefreshCache", BindingFlags.NonPublic | BindingFlags.Instance)!.Invoke(cache, null);
                Assert.NotEqual(oldParent, cache.GetProcessIdentity(pid).parentId);
                Assert.Equal(Process.GetCurrentProcess().StartTime.ToUniversalTime(), cache.GetProcessIdentity(pid).startUtc);
            }
        }

        [Fact]
        public void ProcessAncestryCache_PreservesEtwParentPidAcrossRefreshes()
        {
            // Arrange
            using var cache = new ProcessAncestryCache();
            int myPid = Process.GetCurrentProcess().Id;
            int fakeParentPid = int.MaxValue - 1;
            string myName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;

            // Record the parent process first so its name can be resolved
            cache.RecordProcessStart(fakeParentPid, 0, "explorer", "C:\\Windows\\explorer.exe");

            // Record a high-fidelity ETW-sourced process start (with custom fake parent ID)
            cache.RecordProcessStart(myPid, fakeParentPid, myName, SecurityValidation.GetProcessImagePath(myPid)!);

            // Verify it was written to the cache
            var beforeRefresh = cache.GetParent(myPid);
            Assert.Equal(fakeParentPid, beforeRefresh.parentId);
            Assert.Equal("explorer", beforeRefresh.name);

            // Act: Invoke the private RefreshCache method via reflection
            var refreshMethod = typeof(ProcessAncestryCache).GetMethod(
                "RefreshCache", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(refreshMethod);
            refreshMethod!.Invoke(cache, null);

            // Assert: Verify that the custom parent PID was PRESERVED and not overwritten
            // by the NtQueryInformationProcess parent PID retrieved during refresh!
            var afterRefresh = cache.GetParent(myPid);
            Assert.Equal(fakeParentPid, afterRefresh.parentId);
            Assert.Equal("explorer", afterRefresh.name);
        }

        [Fact]
        public void ProcessAncestryCache_PrunesExitedProcesses()
        {
            // Arrange
            using var cache = new ProcessAncestryCache();
            int fakePid = 999999; // Non-existent PID
            int fakeParent = 1111;

            cache.RecordProcessStart(fakePid, fakeParent, "ghost", "C:\\temp\\ghost.exe");

            // Verify before refresh
            var before = cache.GetParent(fakePid);
            Assert.Equal(fakeParent, before.parentId);

            // Act: Refresh cache (this will see that PID 999999 is not running and start tracking it in dead PIDs)
            var refreshMethod = typeof(ProcessAncestryCache).GetMethod(
                "RefreshCache", BindingFlags.NonPublic | BindingFlags.Instance);
            refreshMethod!.Invoke(cache, null);

            // Manually age the dead PID retention so it gets pruned on the next refresh
            var deadPidRetention = (System.Collections.Concurrent.ConcurrentDictionary<int, DateTimeOffset>)
                typeof(ProcessAncestryCache).GetField("_deadPidRetention", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(cache)!;
            deadPidRetention[fakePid] = DateTimeOffset.UtcNow.AddMinutes(-2);

            // Run another refresh to trigger pruning
            refreshMethod!.Invoke(cache, null);

            // Assert: It should have been pruned and return unknown/0
            var after = cache.GetParent(fakePid);
            Assert.Equal(0, after.parentId);
            Assert.Equal("unknown", after.name);
        }
    }
}
