using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>Append-only hash chain. A trusted checkpoint must be retained off-host
    /// to detect a fully rewritten history or a truncated suffix.</summary>
    public sealed class EvidenceLedger
    {
        private readonly string _path;
        private readonly object _gate = new();
        private LedgerCheckpoint? _tail;
        private long _length = -1;
        public EvidenceLedger(string path) => _path = Path.GetFullPath(path);

        public LedgerCheckpoint Append(string payload, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var parsed = JsonDocument.Parse(payload);
            lock (_gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                // Exclusive writer for the entire verify/append operation.
                using var file = new FileStream(_path, FileMode.OpenOrCreate, FileAccess.ReadWrite,
                    FileShare.Read | FileShare.Delete);
                if (file.Length > 0)
                {
                    file.Seek(-1, SeekOrigin.End);
                    if (file.ReadByte() != '\n') throw new InvalidDataException("Incomplete ledger record; refusing append.");
                    file.Position = 0;
                }
                if (_tail == null || _length != file.Length)
                {
                    using var reader = new StreamReader(file, Encoding.UTF8, true, 4096, leaveOpen: true);
                    _tail = Verify(reader, cancellationToken: cancellationToken);
                }
                var record = new LedgerRecord
                {
                    Sequence = checked(_tail.Sequence + 1), PreviousHash = _tail.Hash, Payload = payload
                };
                record.Hash = Hash(record);
                var json = JsonSerializer.Serialize(record);
                if (json.Length > 4 * 1024 * 1024) throw new InvalidDataException("Oversized ledger record.");
                var bytes = Encoding.UTF8.GetBytes(json + "\n");
                if (file.Length + bytes.Length > 20L * 1024 * 1024)
                    throw new IOException("Daily evidence ledger exceeds 20 MB; audit integrity is degraded.");
                file.Seek(0, SeekOrigin.End);
                file.Write(bytes, 0, bytes.Length);
                file.Flush(flushToDisk: true);
                _length = file.Length;
                _tail = new LedgerCheckpoint { Sequence = record.Sequence, Hash = record.Hash };
                return new LedgerCheckpoint { Sequence = record.Sequence, Hash = record.Hash };
            }
        }

        public static LedgerCheckpoint Verify(TextReader reader, LedgerCheckpoint? trustedCheckpoint = null,
            CancellationToken cancellationToken = default)
        {
            var tail = new LedgerCheckpoint();
            bool anchorSeen = trustedCheckpoint == null || trustedCheckpoint.Sequence == 0 && trustedCheckpoint.Hash == "GENESIS";
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (line.Length > 4 * 1024 * 1024 || string.IsNullOrWhiteSpace(line))
                    throw new InvalidDataException("Oversized or empty ledger record.");
                var record = JsonSerializer.Deserialize<LedgerRecord>(line) ?? throw new InvalidDataException("Null ledger record.");
                using var payload = JsonDocument.Parse(record.Payload);
                if (record.Version != 1 || record.Sequence != tail.Sequence + 1 || record.PreviousHash != tail.Hash || record.Hash != Hash(record))
                    throw new InvalidDataException($"Evidence chain mismatch at sequence {tail.Sequence + 1}.");
                tail = new LedgerCheckpoint { Sequence = record.Sequence, Hash = record.Hash };
                if (trustedCheckpoint != null && tail.Sequence == trustedCheckpoint.Sequence)
                {
                    if (tail.Hash != trustedCheckpoint.Hash) throw new InvalidDataException("Trusted checkpoint mismatch.");
                    anchorSeen = true;
                }
            }
            if (!anchorSeen) throw new InvalidDataException("Trusted checkpoint missing: history was truncated or replaced.");
            return tail;
        }

        private static string Hash(LedgerRecord record)
        {
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(
                "sentinel-ledger-v1\n" + record.Sequence.ToString(CultureInfo.InvariantCulture) + "\n" +
                record.PreviousHash + "\n" + record.Payload))).Replace("-", "").ToLowerInvariant();
        }
    }

    public sealed class LedgerCheckpoint
    {
        public long Sequence { get; set; }
        public string Hash { get; set; } = "GENESIS";
    }

    public sealed class AuditChainCheckpoint
    {
        public string File { get; set; } = "";
        public long Sequence { get; set; }
        public string Hash { get; set; } = "";
    }

    public sealed class LedgerRecord
    {
        public int Version { get; set; } = 1;
        public long Sequence { get; set; }
        public string PreviousHash { get; set; } = "";
        public string Payload { get; set; } = "";
        public string Hash { get; set; } = "";
    }
}
