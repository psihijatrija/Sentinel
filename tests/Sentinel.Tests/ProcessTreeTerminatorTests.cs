using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class ProcessTreeTerminatorTests
    {
        private sealed class Target : IProcessTreeTarget
        {
            public int ProcessId { get; set; }
            public long CreationTime { get; set; }
            public bool CanTerminate { get; set; } = true;
            public bool HasExited { get; set; }
            public bool Fails { get; set; }
            public bool Disposed { get; private set; }
            public int Attempts { get; private set; }
            public Action? OnTerminate { get; set; }
            public bool TerminateAndWait(int timeoutMilliseconds)
            {
                Attempts++;
                OnTerminate?.Invoke();
                return HasExited = !Fails;
            }
            public void Dispose() => Disposed = true;
        }

        private sealed class Operations : IProcessTreeOperations
        {
            public readonly Dictionary<int, Target> Targets = new();
            public readonly List<ProcessTreeEntry> Entries = new();
            public Action? OnSnapshot { get; set; }
            public IReadOnlyList<ProcessTreeEntry> Snapshot() { OnSnapshot?.Invoke(); return Entries.ToArray(); }
            public IProcessTreeTarget? Open(int pid) => Targets.TryGetValue(pid, out var t) ? t : null;
            public Target Add(int pid, int parent, long created)
            {
                var t = new Target { ProcessId = pid, CreationTime = created };
                Targets.Add(pid, t);
                Entries.Add(new ProcessTreeEntry(pid, parent));
                return t;
            }
        }

        [Fact]
        public void TerminatesChildrenAndGrandchildren_LeavesUnrelatedProcessAlone()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 10);
            var child = ops.Add(500002, root.ProcessId, 20);
            var grandchild = ops.Add(500003, child.ProcessId, 30);
            var unrelated = ops.Add(500004, 0, 5);
            var result = new ProcessTreeTerminator(ops).Terminate(root.ProcessId);
            Assert.True(result.Success);
            Assert.Equal(new[] { root.ProcessId, child.ProcessId, grandchild.ProcessId }.OrderBy(p => p),
                result.ExitedProcessIds.OrderBy(p => p));
            Assert.Equal(0, unrelated.Attempts);
            Assert.All(new[] { root, child, grandchild }, t => Assert.True(t.Disposed));
        }

        [Fact]
        public void RefusesProtectedDescendant_ReportsIncompleteContainment()
        {
            var ops = new Operations();
            ops.Add(500001, 0, 10);
            var child = ops.Add(500002, 500001, 20);
            child.CanTerminate = false;
            var result = new ProcessTreeTerminator(ops).Terminate(500001);
            Assert.True(result.RootExited);
            Assert.False(result.Success);
            Assert.Contains(child.ProcessId, result.RefusedProcessIds);
            Assert.Equal(0, child.Attempts);
        }

        [Fact]
        public void DoesNotAttachOlderProcessToReusedParentPid()
        {
            var ops = new Operations();
            ops.Add(500001, 0, 100);
            var older = ops.Add(500002, 500001, 50);
            var result = new ProcessTreeTerminator(ops).Terminate(500001);
            Assert.True(result.Success);
            Assert.Equal(0, older.Attempts);
            Assert.True(older.Disposed);
        }

        [Fact]
        public void RefusesRootWhenExpectedProcessGenerationDiffers()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 100);
            var result = new ProcessTreeTerminator(ops).Terminate(root.ProcessId, expectedCreationTime: 50);
            Assert.False(result.Success);
            Assert.Equal(0, root.Attempts);
            Assert.Contains(root.ProcessId, result.RefusedProcessIds);
        }

        [Fact]
        public void FailedChildTerminationCannotReportSuccessfulTreeContainment()
        {
            var ops = new Operations();
            ops.Add(500001, 0, 10);
            var child = ops.Add(500002, 500001, 20);
            child.Fails = true;
            var result = new ProcessTreeTerminator(ops).Terminate(500001);
            Assert.False(result.Success);
            Assert.Contains(child.ProcessId, result.FailedProcessIds);
        }

        [Fact]
        public void RescansForDescendantSpawnedDuringTermination()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 10);
            root.OnTerminate = () => ops.Add(500002, root.ProcessId, 20);
            var result = new ProcessTreeTerminator(ops).Terminate(root.ProcessId);
            Assert.True(result.Success);
            Assert.Contains(500002, result.ExitedProcessIds);
        }

        [Fact]
        public void SnapshotFailureDoesNotBecomeSuccess_AndDisposesHandles()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 10);
            ops.OnSnapshot = () => throw new InvalidOperationException("snapshot unavailable");
            var result = new ProcessTreeTerminator(ops).Terminate(root.ProcessId);
            Assert.False(result.Success);
            Assert.False(result.DiscoveryComplete);
            Assert.Equal("snapshot unavailable", result.Error);
            Assert.True(root.Disposed);
        }

        [Fact]
        public void RepeatedSpawningIsBounded_AndReportedAsIncomplete()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 10);
            int nextPid = 500002;
            ops.OnSnapshot = () => ops.Add(nextPid++, root.ProcessId, 20);
            var result = new ProcessTreeTerminator(ops).Terminate(root.ProcessId);
            Assert.False(result.Success);
            Assert.False(result.DiscoveryComplete);
            Assert.Equal(500006, nextPid);
        }

        [Fact]
        public void MissingRootCannotVerifyFormerDescendants()
        {
            var result = new ProcessTreeTerminator(new Operations()).Terminate(500001);
            Assert.True(result.RootExited);
            Assert.False(result.Success);
        }

        [Fact]
        public void CancellationReleasesOpenedProcessHandles()
        {
            var ops = new Operations();
            var root = ops.Add(500001, 0, 10);
            using var cancellation = new CancellationTokenSource();
            ops.OnSnapshot = cancellation.Cancel;
            Assert.Throws<OperationCanceledException>(() =>
                new ProcessTreeTerminator(ops).Terminate(root.ProcessId, cancellationToken: cancellation.Token));
            Assert.True(root.Disposed);
            Assert.Equal(0, root.Attempts);
        }
    }
}
