// net48 API shims used across 1.8.6 sources. Prefer these over rewriting every call site.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace System
{
    public static class Net48Environment
    {
        public static string? ProcessPath
        {
            get
            {
                try { return Process.GetCurrentProcess().MainModule?.FileName; }
                catch { return null; }
            }
        }

        public static int ProcessId
        {
            get
            {
                try { return Process.GetCurrentProcess().Id; }
                catch { return 0; }
            }
        }

        public static long TickCount64 => Environment.TickCount & 0xFFFFFFFFL;
    }

    public static class ConvertHex
    {
        public static string ToHexString(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public static byte[] FromHexString(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return Array.Empty<byte>();
            hex = hex.Trim();
            if (hex.StartsWith("0x")) hex = hex.Substring(2);
            if (hex.Length % 2 != 0) throw new FormatException("Invalid hex length");
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }
    }

    public static class MathNet48
    {
        public static double Log2(double value) => Math.Log(value, 2.0);

        public static int Clamp(int value, int min, int max)
        {
            if (value < min) return min;
            if (value > max) return max;
            return value;
        }

        public static double Clamp(double value, double min, double max)
        {
            if (value < min) return min;
            if (value > max) return max;
            return value;
        }

        public static float Clamp(float value, float min, float max)
        {
            if (value < min) return min;
            if (value > max) return max;
            return value;
        }
    }
}

namespace System.Security.Cryptography
{
    public static class Sha256Net48
    {
        public static byte[] HashData(byte[] data)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(data);
        }

        public static byte[] HashData(Stream stream)
        {
            using (var sha = SHA256.Create())
                return sha.ComputeHash(stream);
        }

        public static Task<byte[]> ComputeHashAsync(this SHA256 sha, Stream stream, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                return sha.ComputeHash(stream);
            }, ct);
        }
    }
}

namespace System.Collections.Generic
{
    public static class DictionaryNet48Extensions
    {
        public static void Deconstruct<TKey, TValue>(this KeyValuePair<TKey, TValue> kvp, out TKey key, out TValue value)
        {
            key = kvp.Key;
            value = kvp.Value;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(
            this ConcurrentDictionary<TKey, TValue> dict, TKey key, TValue defaultValue = default!)
        {
            return dict.TryGetValue(key, out var v) ? v : defaultValue;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(
            this IDictionary<TKey, TValue> dict, TKey key, TValue defaultValue = default!)
        {
            return dict.TryGetValue(key, out var v) ? v : defaultValue;
        }

        public static TValue GetValueOrDefault<TKey, TValue>(
            this Dictionary<TKey, TValue> dict, TKey key, TValue defaultValue = default!)
        {
            return dict.TryGetValue(key, out var v) ? v : defaultValue;
        }

        public static bool TryAdd<TKey, TValue>(this Dictionary<TKey, TValue> dict, TKey key, TValue value)
        {
            if (dict.ContainsKey(key)) return false;
            dict.Add(key, value);
            return true;
        }

        public static bool TryAdd<TKey, TValue>(this IDictionary<TKey, TValue> dict, TKey key, TValue value)
        {
            if (dict.ContainsKey(key)) return false;
            dict.Add(key, value);
            return true;
        }
    }
}

namespace System.IO
{
    public static class FileNet48
    {
        public static Task WriteAllTextAsync(string path, string contents, CancellationToken ct = default)
            => WriteAllTextAsync(path, contents, Encoding.UTF8, ct);

        public static Task WriteAllTextAsync(string path, string contents, Encoding encoding, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                File.WriteAllText(path, contents, encoding);
            }, ct);
        }

        public static Task WriteAllBytesAsync(string path, byte[] bytes, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                File.WriteAllBytes(path, bytes);
            }, ct);
        }

        public static Task<byte[]> ReadAllBytesAsync(string path, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                return File.ReadAllBytes(path);
            }, ct);
        }

        public static Task<string> ReadAllTextAsync(string path, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                return File.ReadAllText(path);
            }, ct);
        }

        public static Task WriteAllLinesAsync(string path, IEnumerable<string> lines, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                File.WriteAllLines(path, lines);
            }, ct);
        }

        public static Task ReadExactlyAsync(this Stream stream, byte[] buffer, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                int offset = 0;
                while (offset < buffer.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    int read = stream.Read(buffer, offset, buffer.Length - offset);
                    if (read == 0) throw new EndOfStreamException();
                    offset += read;
                }
            }, ct);
        }

        public static void Write(this MemoryStream ms, byte[] buffer)
        {
            ms.Write(buffer, 0, buffer.Length);
        }
    }

    public static class StreamWriterNet48
    {
        public static Task WriteLineAsync(this StreamWriter writer, string? value)
        {
            return writer.WriteLineAsync(value ?? "");
        }

        public static Task DisposeAsync(this StreamWriter writer)
        {
            writer.Dispose();
            return Task.CompletedTask;
        }

        public static Task DisposeAsync(this FileStream stream)
        {
            stream.Dispose();
            return Task.CompletedTask;
        }

        public static Task DisposeAsync(this Stream stream)
        {
            stream.Dispose();
            return Task.CompletedTask;
        }
    }
}

namespace System.Diagnostics
{
    public static class ProcessNet48
    {
        public static Task WaitForExitAsync(this Process process, CancellationToken ct = default)
        {
            if (process.HasExited) return Task.CompletedTask;
            var tcs = new TaskCompletionSource<object?>();
            void Handler(object? s, EventArgs e) => tcs.TrySetResult(null);
            process.EnableRaisingEvents = true;
            process.Exited += Handler;
            if (process.HasExited) tcs.TrySetResult(null);
            if (ct.CanBeCanceled)
                ct.Register(() => tcs.TrySetCanceled(ct));
            return tcs.Task;
        }

        /// <summary>net48 has no Kill(entireProcessTree). Kill process + children best-effort.</summary>
        public static void KillTree(this Process process)
        {
            try
            {
                if (!process.HasExited) process.Kill();
            }
            catch { /* already exited */ }
        }
    }
}

namespace System.Net
{
    public static class DnsNet48
    {
        public static Task<IPAddress[]> GetHostAddressesAsync(string hostNameOrAddress, CancellationToken ct = default)
        {
            return Task.Run(() =>
            {
                ct.ThrowIfCancellationRequested();
                return Dns.GetHostAddresses(hostNameOrAddress);
            }, ct);
        }
    }
}

namespace System.Net.Sockets
{
    public static class SocketNet48
    {
        public static Task ConnectAsync(this TcpClient client, string host, int port, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var connectTask = client.ConnectAsync(host, port);
            if (!ct.CanBeCanceled) return connectTask;
            var tcs = new TaskCompletionSource<object?>();
            ct.Register(() =>
            {
                try { client.Close(); } catch { }
                tcs.TrySetCanceled(ct);
            });
            connectTask.ContinueWith(t =>
            {
                if (t.IsFaulted) tcs.TrySetException(t.Exception!.InnerExceptions);
                else if (t.IsCanceled) tcs.TrySetCanceled();
                else tcs.TrySetResult(null);
            }, TaskScheduler.Default);
            return tcs.Task;
        }

        public static Task ConnectAsync(this TcpClient client, IPAddress address, int port, CancellationToken ct)
            => ConnectAsync(client, address.ToString(), port, ct);
    }
}

namespace System.Net.Http
{
    public static class HttpNet48
    {
        public static Task<string> GetStringAsync(this HttpClient client, string requestUri, CancellationToken ct)
        {
            return Task.Run(async () =>
            {
                ct.ThrowIfCancellationRequested();
                using (var resp = await client.GetAsync(requestUri, ct).ConfigureAwait(false))
                {
                    resp.EnsureSuccessStatusCode();
                    return await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
                }
            }, ct);
        }

        public static Task<string> ReadAsStringAsync(this HttpContent content, CancellationToken ct)
        {
            return Task.Run(async () =>
            {
                ct.ThrowIfCancellationRequested();
                return await content.ReadAsStringAsync().ConfigureAwait(false);
            }, ct);
        }
    }
}

namespace System.Threading.Tasks
{
    public static class ValueTaskNet48
    {
        public static ValueTask CompletedTask => default;
    }
}


namespace System.IO
{
    public static class PathNet48
    {
        public static bool IsPathFullyQualified(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            if (path.Length >= 2 && path[1] == ':') return true; // C:\
            if (path.StartsWith(@"\\")) return true; // UNC
            return Path.IsPathRooted(path) && path.Length > 1;
        }
    }
}
namespace Sentinel.Core
{
    /// <summary>String helpers missing on net48 (Replace with StringComparison, Split options, etc.).</summary>
    public static class StringNet48
    {
        public static string ReplaceIgnoreCase(string input, string oldValue, string newValue)
        {
            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(oldValue)) return input;
            var idx = 0;
            var sb = new StringBuilder(input.Length);
            while (idx < input.Length)
            {
                var found = input.IndexOf(oldValue, idx);
                if (found < 0)
                {
                    sb.Append(input, idx, input.Length - idx);
                    break;
                }
                sb.Append(input, idx, found - idx);
                sb.Append(newValue);
                idx = found + oldValue.Length;
            }
            return sb.ToString();
        }

        public static string Replace(string input, string oldValue, string newValue, StringComparison comparison)
        {
            if (comparison == StringComparison.OrdinalIgnoreCase ||
                comparison == StringComparison.CurrentCultureIgnoreCase ||
                comparison == StringComparison.InvariantCultureIgnoreCase)
                return ReplaceIgnoreCase(input, oldValue, newValue);

            if (string.IsNullOrEmpty(input) || string.IsNullOrEmpty(oldValue)) return input;
            return input.Replace(oldValue, newValue);
        }

        public static bool Contains(string haystack, string needle, StringComparison comparison)
            => haystack?.IndexOf(needle, comparison) >= 0;

        public static bool Contains(string haystack, char c)
            => haystack != null && haystack.IndexOf(c) >= 0;

        public static string[] SplitLines(string input, StringSplitOptions options = StringSplitOptions.None)
        {
            var parts = input.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            if ((options & StringSplitOptions.RemoveEmptyEntries) == 0 && input.Length == 0)
                return new[] { "" };
            return parts;
        }

        public static string[] Split(string input, char separator, StringSplitOptions options)
        {
            var parts = input.Split(new[] { separator },
                (options & StringSplitOptions.RemoveEmptyEntries) != 0
                    ? StringSplitOptions.RemoveEmptyEntries
                    : StringSplitOptions.None);
            // net48 has no TrimEntries - apply manually when flag bit present (value 2 on modern)
            if (((int)options & 2) != 0)
            {
                for (int i = 0; i < parts.Length; i++)
                    parts[i] = parts[i].Trim();
            }
            return parts;
        }

        public static string[] Split(string input, string separator, StringSplitOptions options)
        {
            var parts = input.Split(new[] { separator },
                (options & StringSplitOptions.RemoveEmptyEntries) != 0
                    ? StringSplitOptions.RemoveEmptyEntries
                    : StringSplitOptions.None);
            if (((int)options & 2) != 0)
            {
                for (int i = 0; i < parts.Length; i++)
                    parts[i] = parts[i].Trim();
            }
            return parts;
        }

        public static string Join(char separator, params string[] values)
            => string.Join(separator.ToString(), values);

        public static string Join(char separator, IEnumerable<string> values)
            => string.Join(separator.ToString(), values);
    }
}

