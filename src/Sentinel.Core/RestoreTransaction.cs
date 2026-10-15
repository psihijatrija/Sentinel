using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>Write-ahead journal for an explicitly requested quarantine restore.
    /// Never overwrites an existing destination or deletes the original vault.</summary>
    public sealed class RestoreTransaction
    {
        public RestoreTransactionRecord Restore(string vaultPath, string destination, byte[] plain,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            destination = Path.GetFullPath(destination);
            RequireLocalPath(destination);
            if (File.Exists(destination) || Directory.Exists(destination))
                throw new IOException("Restore destination already exists; refusing to overwrite it.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            var record = new RestoreTransactionRecord
            {
                Id = Guid.NewGuid().ToString("N"), Destination = destination,
                Sha256 = Hash(plain), VaultFile = Path.GetFileName(vaultPath), State = "Prepared"
            };
            var journalDirectory = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(vaultPath))!, "RestoreJournal");
            Directory.CreateDirectory(journalDirectory);
            var journal = Path.Combine(journalDirectory, Path.GetFileName(vaultPath) + ".restore-" + record.Id + ".json");
            var staging = destination + ".sentinel-restore-" + record.Id;
            record.StagingPath = staging;
            WriteJournal(journal, record);
            // A crash may leave Prepared + staging; recovery reports it for review.
            using (var output = new FileStream(staging, FileMode.CreateNew, FileAccess.Write, FileShare.Read | FileShare.Delete))
            {
                output.Write(plain, 0, plain.Length);
                output.Flush(flushToDisk: true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            // File.Move is atomic within this directory and refuses overwrite, including races.
            File.Move(staging, destination);
            record.State = "Applied";
            WriteJournal(journal, record);
            if (!Matches(destination, record.Sha256))
                throw new IOException("Restored content failed read-back verification; vault retained.");
            record.State = "Verified";
            WriteJournal(journal, record);
            return record;
        }

        /// <summary>Read-only recovery assessment. Never replays a restoration or trusts
        /// a journal to authorize overwrites, deletion, or execution.</summary>
        public RestoreRecoveryAssessment Inspect(string journalPath)
        {
            using var stream = new FileStream(journalPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (stream.Length > 64 * 1024) throw new InvalidDataException("Restore journal exceeds 64 KiB.");
            var record = JsonSerializer.Deserialize<RestoreTransactionRecord>(stream)
                ?? throw new InvalidDataException("Missing restore journal.");
            if (record.SchemaVersion != 1 || !Guid.TryParseExact(record.Id, "N", out _) ||
                record.Sha256 == null || record.Sha256.Length != 64 ||
                record.Sha256.Any(c => !Uri.IsHexDigit(c)) ||
                (record.State != "Prepared" && record.State != "Applied" && record.State != "Verified") ||
                string.IsNullOrEmpty(record.VaultFile) || Path.GetFileName(record.VaultFile) != record.VaultFile ||
                record.DestinationExistedBefore)
                throw new InvalidDataException("Invalid or unsupported restore journal.");
            RequireLocalPath(record.Destination);
            if (!string.Equals(Path.GetFullPath(record.Destination), record.Destination, StringComparison.OrdinalIgnoreCase) ||
                record.StagingPath != record.Destination + ".sentinel-restore-" + record.Id)
                throw new InvalidDataException("Restore journal contains inconsistent paths.");
            bool verified = !string.IsNullOrEmpty(record.Destination) && File.Exists(record.Destination) &&
                Matches(record.Destination, record.Sha256);
            return new RestoreRecoveryAssessment
            {
                Transaction = record, DestinationMatches = verified,
                Recommendation = verified ? "Destination content matches; retain vault until operator confirms completion" :
                    "Interrupted or changed restore; retain vault and review destination/staging manually"
            };
        }

        private static void RequireLocalPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || !Path.IsPathRooted(path) ||
                path.StartsWith(@"\\", StringComparison.Ordinal) || path.StartsWith("//", StringComparison.Ordinal))
                throw new InvalidDataException("Restore paths must be absolute local paths; network/device paths are refused.");
            foreach (var part in path.Split(new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar, '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (part.Length == 2 && part[1] == ':') continue; // Windows drive root.
                string stem = part.Split('.')[0].ToUpperInvariant();
                if (part.IndexOf(':') >= 0 || part.EndsWith(".", StringComparison.Ordinal) || part.EndsWith(" ", StringComparison.Ordinal) ||
                    stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" ||
                    (stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal)) &&
                        stem[3] >= '1' && stem[3] <= '9'))
                    throw new InvalidDataException("Device names, alternate streams and ambiguous restore paths are refused.");
            }
            // A local-looking path through a junction can otherwise reach a remote target.
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                if ((File.Exists(current) || Directory.Exists(current)) &&
                    (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidDataException("Linked restore paths require manual review.");
                current = Path.GetDirectoryName(current);
            }
        }

        private static void WriteJournal(string path, RestoreTransactionRecord record)
        {
            var temp = path + ".tmp";
            var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.Read | FileShare.Delete))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(flushToDisk: true);
            }
            if (File.Exists(path)) File.Replace(temp, path, null);
            else File.Move(temp, path);
        }

        private static bool Matches(string path, string expected)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Cannot verify a linked restore destination.");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant() == expected;
        }

        private static string Hash(byte[] bytes)
        {
            using var sha = SHA256.Create();
            return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
    }

    public sealed class RestoreTransactionRecord
    {
        public int SchemaVersion { get; set; } = 1;
        public string Id { get; set; } = "";
        public string VaultFile { get; set; } = "";
        public string Destination { get; set; } = "";
        public string StagingPath { get; set; } = "";
        public string Sha256 { get; set; } = "";
        public string State { get; set; } = "";
        public bool DestinationExistedBefore { get; set; }
        public string AuthorizationContext { get; set; } = "Explicit restore API invocation; caller authorization must be enforced at the IPC boundary";
    }

    public sealed class RestoreRecoveryAssessment
    {
        public RestoreTransactionRecord Transaction { get; set; } = new();
        public bool DestinationMatches { get; set; }
        public string Recommendation { get; set; } = "";
    }
}
