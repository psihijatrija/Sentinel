using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class BoundedIpcRequestTests
    {
        [Fact]
        public async Task AcceptsSingleRequestAndRejectsOversizedUnauthenticatedInput()
        {
            Assert.Equal("{\"op\":\"ping\"}", await BoundedIpcRequest.ReadAsync(
                new StringReader("{\"op\":\"ping\"}\r\nignored"), TimeSpan.FromSeconds(1), CancellationToken.None));
            Assert.Equal(BoundedIpcRequest.MaxCharacters, (await BoundedIpcRequest.ReadAsync(
                new StringReader(new string('a', BoundedIpcRequest.MaxCharacters) + "\n"), TimeSpan.FromSeconds(1), CancellationToken.None)).Length);
            await Assert.ThrowsAsync<InvalidDataException>(() => BoundedIpcRequest.ReadAsync(
                new StringReader(new string('a', BoundedIpcRequest.MaxCharacters + 1)), TimeSpan.FromSeconds(1), CancellationToken.None));
        }

        private sealed class StalledReader : TextReader
        {
            public override Task<int> ReadAsync(char[] buffer, int index, int count) =>
                new TaskCompletionSource<int>().Task;
        }

        [Fact]
        public async Task StalledClientCannotHoldPrivilegedPipeIndefinitely()
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BoundedIpcRequest.ReadAsync(
                new StalledReader(), TimeSpan.FromMilliseconds(20), CancellationToken.None));
            using var cancelled = new CancellationTokenSource();
            cancelled.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BoundedIpcRequest.ReadAsync(
                new StalledReader(), TimeSpan.FromSeconds(5), cancelled.Token));
        }
    }
}
