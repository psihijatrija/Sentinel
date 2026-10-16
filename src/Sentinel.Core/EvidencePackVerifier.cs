using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>Checks sealed pack contents without requiring an endpoint's secret key.
    /// Content consistency alone is not proof of origin.</summary>
    public sealed class EvidencePackVerifier
    {
        public EvidencePackVerification Verify(string directory, CancellationToken cancellationToken = default)
        {
            directory = Path.GetFullPath(directory);
            if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Evidence directory must not be a link.");
            var result = new EvidencePackVerification();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var manifest = Path.Combine(directory, "MANIFEST.sha256");
            RejectLink(manifest);
            using var manifestStream = new FileStream(manifest, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var reader = new StreamReader(manifestStream);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (line.StartsWith("#", StringComparison.Ordinal) || line.Length == 0) continue;
                if (line.Length < 67 || line.Substring(64, 2) != "  ")
                    throw new InvalidDataException("Invalid manifest entry.");
                var expected = line.Substring(0, 64);
                var name = line.Substring(66);
                // Packs currently contain flat files. Do not permit traversal, NTFS ADS,
                // rooted paths, nested paths, or duplicate/case-aliased entries.
                if (name.Length == 0 || name == "." || name == ".." || name.IndexOfAny(new[] { '/', '\\', ':' }) >= 0 ||
                    name.EndsWith(".", StringComparison.Ordinal) || name.EndsWith(" ", StringComparison.Ordinal) ||
                    !seen.Add(name) || !IsHash(expected))
                    throw new InvalidDataException("Unsafe or duplicate manifest filename/hash.");
                var path = Path.Combine(directory, name);
                RejectLink(path);
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var sha = SHA256.Create();
                var actual = BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
                if (!string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"Evidence hash mismatch: {name}");
                result.VerifiedFiles.Add(name);
            }
            if (seen.Count == 0) throw new InvalidDataException("Empty manifest does not verify any evidence.");
            result.ContentHashesVerified = true;
            return result;
        }

        private static void RejectLink(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Evidence links are not supported.");
        }

        private static bool IsHash(string hash)
        {
            foreach (var c in hash)
                if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F')) return false;
            return hash.Length == 64;
        }
    }

    public sealed class EvidencePackVerification
    {
        public bool ContentHashesVerified { get; set; }
        public bool OriginAuthenticated { get; set; } // Requires an independently trusted signature/key.
        public string Scope { get; set; } = "Manifest-listed content only; origin, unlisted files and custody are not authenticated";
        public List<string> VerifiedFiles { get; set; } = new();
    }
}
