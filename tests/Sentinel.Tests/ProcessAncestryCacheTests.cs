using System;
using System.Collections.Generic;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class ProcessAncestryCacheTests
    {
        private static ProcessAncestryCache.Identity Process(int generation, string name = "child", int parent = 11)
            => new() { Pid = 42, CreationTicks = generation, Name = name, ParentPid = parent, ImagePath = @"C:\Tools\" + name + ".exe" };

        [Fact]
        public void SameGeneration_PreservesRecordedParent()
        {
            using var cache = new ProcessAncestryCache(_ => Process(1), false);
            cache.RecordProcessStart(42, 99, "child", @"C:\Tools\child.exe");
            Assert.True(cache.TryGetLiveProcessInfo(42, out var info));
            Assert.Equal(99, info.parentId);
        }

        [Fact]
        public void ReusedPid_ReplacesOldImageAndParentWithoutAnObservedExit()
        {
            int generation = 1;
            using var cache = new ProcessAncestryCache(_ => generation == 1 ? Process(1, "gamingservices") : Process(2, "git", 22), false);
            cache.RecordProcessStart(42, 99, "gamingservices", @"C:\Tools\gamingservices.exe");
            generation = 2;
            Assert.True(cache.TryGetLiveProcessInfo(42, out var info));
            Assert.Equal(22, info.parentId);
            Assert.Equal("git", info.name);
            Assert.Equal(@"C:\Tools\git.exe", info.imagePath);
        }

        [Fact]
        public void DeadProcess_HistoryCannotBecomeALiveResponseTarget()
        {
            bool living = true;
            using var cache = new ProcessAncestryCache(_ => living ? Process(1) : null, false);
            cache.RecordProcessStart(42, 99, "child", @"C:\Tools\child.exe");
            living = false;
            Assert.False(cache.TryGetLiveProcessInfo(42, out _));
            Assert.Equal("child", cache.GetProcessInfo(42).name);
            var now = DateTimeOffset.UtcNow;
            cache.PruneDeadEntries(new HashSet<int>(), now);
            cache.PruneDeadEntries(new HashSet<int>(), now.AddSeconds(61));
            Assert.Equal("unknown", cache.GetProcessInfo(42).name);
        }

        [Fact]
        public void DelayedEvent_ForOldImageCannotReplaceNewProcess()
        {
            using var cache = new ProcessAncestryCache(_ => Process(2, "git", 22), false);
            cache.RecordProcessStart(42, 99, "gamingservices", @"C:\Tools\gamingservices.exe");
            Assert.True(cache.TryGetLiveProcessInfo(42, out var info));
            Assert.Equal(22, info.parentId);
            Assert.Equal("git", info.name);
        }

        [Fact]
        public void UnknownCreationTime_IsNeverALiveResponseTarget()
        {
            using var cache = new ProcessAncestryCache(_ => Process(0), false);
            Assert.False(cache.TryGetLiveProcessInfo(42, out _));
        }
    }
}
