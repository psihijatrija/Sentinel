using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Sentinel.Core
{
    public interface IIncidentStateStore
    {
        IncidentStateSnapshot Load();
        void Save(IncidentStateSnapshot snapshot);
    }

    public sealed class IncidentStateSnapshot
    {
        public int SchemaVersion { get; set; } = 1;
        public long TotalCreated { get; set; }
        public List<Incident> Incidents { get; set; } = new();
    }

    /// <summary>Bounded, atomic investigation state. This file is never response authority.</summary>
    public sealed class IncidentStateStore : IIncidentStateStore
    {
        private const int MaximumBytes = 20 * 1024 * 1024;
        private readonly string _path;
        private readonly object _gate = new();
        private bool _readFailed;

        public IncidentStateStore(string path) => _path = Path.GetFullPath(path);

        public IncidentStateSnapshot Load()
        {
            lock (_gate)
            {
                if (!File.Exists(_path)) return new IncidentStateSnapshot();
                try
                {
                    using var stream = new FileStream(_path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    if (stream.Length > MaximumBytes) throw new InvalidDataException("Incident state exceeds 20 MiB.");
                    var state = JsonSerializer.Deserialize<IncidentStateSnapshot>(stream)
                        ?? throw new InvalidDataException("Empty incident state.");
                    Validate(state);
                    return state;
                }
                catch
                {
                    // Preserve unreadable evidence instead of replacing it with an empty state.
                    _readFailed = true;
                    throw; // Caller logs degradation; this layer must not hide a read failure.
                }
            }
        }

        public void Save(IncidentStateSnapshot snapshot)
        {
            lock (_gate)
            {
                if (_readFailed) throw new InvalidDataException("Unreadable incident state retained; automatic overwrite refused.");
                Validate(snapshot);
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                string temporary = _path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
                    {
                        using var bounded = new LimitedWriter(output, MaximumBytes);
                        JsonSerializer.Serialize(bounded, snapshot);
                        bounded.Flush();
                        output.Flush(true);
                    }
                    if (File.Exists(_path)) File.Replace(temporary, _path, null);
                    else File.Move(temporary, _path);
                }
                finally
                {
                    if (File.Exists(temporary)) File.Delete(temporary);
                }
            }
        }

        private sealed class LimitedWriter : Stream
        {
            private readonly Stream _output;
            private readonly long _limit;
            public LimitedWriter(Stream output, long limit) { _output = output; _limit = limit; }
            public override bool CanRead => false;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => _output.Length;
            public override long Position { get => _output.Position; set => throw new NotSupportedException(); }
            public override void Flush() => _output.Flush();
            public override void Write(byte[] buffer, int offset, int count)
            {
                if (_output.Position + count > _limit) throw new InvalidDataException("Incident state exceeds 20 MiB.");
                _output.Write(buffer, offset, count);
            }
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
        }

        private static void Validate(IncidentStateSnapshot state)
        {
            if (state.SchemaVersion != 1 || state.TotalCreated < 0 || state.Incidents == null ||
                state.Incidents.Count > 10000 || state.Incidents.Any(i => i == null || string.IsNullOrWhiteSpace(i.Id) ||
                i.Detections == null || i.Detections.Any(d => d == null || d.DetectionEvent == null) ||
                i.InvolvedPids == null || i.Hashes == null || !Enum.IsDefined(typeof(IncidentState), i.State) ||
                !Enum.IsDefined(typeof(IncidentSeverity), i.Severity)) ||
                state.Incidents.Select(i => i.Id).Distinct(StringComparer.Ordinal).Count() != state.Incidents.Count)
                throw new InvalidDataException("Invalid or unsupported incident state.");
        }
    }
}
