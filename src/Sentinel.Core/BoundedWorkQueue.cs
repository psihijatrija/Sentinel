using System;
using System.Linq;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>Fixed concurrency and bounded pending work. Overload is observable, never an unbounded task backlog.</summary>
    internal sealed class BoundedWorkQueue<T> : IAsyncDisposable
    {
        private readonly Channel<T> _channel;
        private readonly CancellationTokenSource _stop = new();
        private readonly Task _completion;
        private readonly Action<Exception> _onError;
        private int _stopped;

        public BoundedWorkQueue(int capacity, int concurrency,
            Func<T, CancellationToken, Task> process, Action onDropped, Action<Exception> onError)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            if (concurrency <= 0) throw new ArgumentOutOfRangeException(nameof(concurrency));
            _onError = onError ?? throw new ArgumentNullException(nameof(onError));
            if (process == null) throw new ArgumentNullException(nameof(process));
            if (onDropped == null) throw new ArgumentNullException(nameof(onDropped));
            _channel = Channel.CreateBounded<T>(new BoundedChannelOptions(capacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = concurrency == 1,
                SingleWriter = false
            }, _ => onDropped());
            _completion = Task.WhenAll(Enumerable.Range(0, concurrency).Select(_ => Task.Run(async () =>
            {
                try
                {
                    while (await _channel.Reader.WaitToReadAsync(_stop.Token).ConfigureAwait(false))
                    {
                        while (!_stop.IsCancellationRequested && _channel.Reader.TryRead(out var item))
                        {
                            try { await process(item, _stop.Token).ConfigureAwait(false); }
                            catch (OperationCanceledException) when (_stop.IsCancellationRequested) { return; }
                            catch (Exception ex) { _onError(ex); }
                        }
                    }
                }
                catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
            })).ToArray());
        }

        public bool TryEnqueue(T item) => Volatile.Read(ref _stopped) == 0 && _channel.Writer.TryWrite(item);
        public Task Completion => _completion;

        public async ValueTask DisposeAsync()
        {
            Stop();
            await Completion.ConfigureAwait(false);
            _stop.Dispose();
        }

        public void Stop()
        {
            if (Interlocked.Exchange(ref _stopped, 1) != 0) return;
            _channel.Writer.TryComplete();
            _stop.Cancel();
        }
    }
}
