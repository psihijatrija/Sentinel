using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Sentinel.Core
{
    /// <summary>Caps unauthenticated pipe input before parsing or dispatching privileged operations.</summary>
    public static class BoundedIpcRequest
    {
        public const int MaxCharacters = 16 * 1024;
        public static async Task<string> ReadAsync(TextReader reader, TimeSpan timeout, CancellationToken ct)
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
            deadline.CancelAfter(timeout);
            var expired = Task.Delay(Timeout.Infinite, deadline.Token);
            var buffer = new char[256];
            var text = new System.Text.StringBuilder();
            while (true)
            {
                var read = reader.ReadAsync(buffer, 0, buffer.Length);
                if (await Task.WhenAny(read, expired).ConfigureAwait(false) != read)
                    throw new OperationCanceledException("IPC request read timed out or was cancelled", deadline.Token);
                var count = await read.ConfigureAwait(false);
                if (count == 0) return text.ToString();
                for (int i = 0; i < count; i++)
                {
                    if (buffer[i] == '\n') return text.ToString().TrimEnd('\r');
                    if (text.Length >= MaxCharacters) throw new InvalidDataException("IPC request exceeds size limit");
                    text.Append(buffer[i]);
                }
            }
        }
    }
}
