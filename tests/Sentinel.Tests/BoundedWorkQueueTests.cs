using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class BoundedWorkQueueTests
    {
        [Fact]
        public async Task BurstUsesExactlyTwoWorkersAndReportsEveryEviction()
        {
            var bothActive = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var drained = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            int active = 0, entered = 0, finished = 0, dropped = 0, excess = 0;
            var errors = new ConcurrentQueue<Exception>();
            var queue = new BoundedWorkQueue<int>(3, 2, async (item, ct) =>
            {
                if (Interlocked.Increment(ref active) > 2) Interlocked.Increment(ref excess);
                if (Interlocked.Increment(ref entered) == 2) bothActive.TrySetResult(true);
                try { await release.Task; }
                finally { Interlocked.Decrement(ref active); }
                if (Interlocked.Increment(ref finished) == 5) drained.TrySetResult(true);
            }, () => Interlocked.Increment(ref dropped), errors.Enqueue);
            try
            {
                queue.TryEnqueue(-1);
                queue.TryEnqueue(-2);
                Assert.Same(bothActive.Task, await Task.WhenAny(bothActive.Task, Task.Delay(5000)));
                Parallel.For(0, 1000, item => Assert.True(queue.TryEnqueue(item)));
                Assert.Equal(997, dropped);
                Assert.Equal(2, entered);
                release.TrySetResult(true);
                Assert.Same(drained.Task, await Task.WhenAny(drained.Task, Task.Delay(5000)));
                Assert.Equal(0, excess);
                Assert.Empty(errors);
            }
            finally { release.TrySetResult(true); await queue.DisposeAsync(); }
        }

        [Fact]
        public async Task OverloadEvictsOldestWithoutCreatingMoreWorkers()
        {
            var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var drained = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var seen = new ConcurrentQueue<int>();
            int dropped = 0;
            var errors = new ConcurrentQueue<Exception>();
            var queue = new BoundedWorkQueue<int>(2, 1, async (item, ct) =>
            {
                seen.Enqueue(item);
                if (item == 0) { entered.TrySetResult(true); await release.Task; }
                if (item == 3) drained.TrySetResult(true);
            }, () => Interlocked.Increment(ref dropped), errors.Enqueue);
            try
            {
                Assert.True(queue.TryEnqueue(0));
                Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(5000)));
                queue.TryEnqueue(1);
                queue.TryEnqueue(2);
                queue.TryEnqueue(3);
                Assert.Equal(1, dropped);
                Assert.Equal(new[] { 0 }, seen.ToArray());
                release.TrySetResult(true);
                Assert.Same(drained.Task, await Task.WhenAny(drained.Task, Task.Delay(5000)));
                Assert.Equal(new[] { 0, 2, 3 }, seen.ToArray());
                Assert.Empty(errors);
            }
            finally { release.TrySetResult(true); queue.Stop(); await queue.Completion; }
            Assert.False(queue.TryEnqueue(4));
        }

        [Fact]
        public async Task FailedItemDoesNotStopFollowingWorkAndShutdownCancelsActiveWork()
        {
            var active = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var errors = new ConcurrentQueue<Exception>();
            var queue = new BoundedWorkQueue<int>(4, 1, async (item, ct) =>
            {
                if (item == 0) throw new InvalidOperationException("fixture");
                active.TrySetResult(true);
                await Task.Delay(Timeout.Infinite, ct);
            }, () => { }, errors.Enqueue);
            try
            {
                queue.TryEnqueue(0);
                queue.TryEnqueue(1);
                Assert.Same(active.Task, await Task.WhenAny(active.Task, Task.Delay(5000)));
                Assert.Single(errors);
            }
            finally { queue.Stop(); }
            Assert.Same(queue.Completion, await Task.WhenAny(queue.Completion, Task.Delay(5000)));
            await queue.Completion;
        }
    }
}
