using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace Sentinel.Core
{
    /// <summary>
    /// Bounded, fail-closed inspection of archive / disk-image containers (ZIP and, at a
    /// shallow level, ISO / IMG disk images) for the content-smuggling shapes an attacker
    /// uses to slip a payload past extension-based scanning:
    ///
    ///   * zip bomb        - a small container whose declared uncompressed size (or observed
    ///                       decompressed bytes) explodes far beyond the container size, or
    ///                       whose per-entry compression ratio is pathological.
    ///   * nested archive  - an archive inside an archive inside an archive (evasion depth).
    ///   * embedded payload- a PE (MZ) or scripting host file carried inside the container.
    ///
    /// HARD CONSTRAINTS (mirrors the fail-closed caps already used in FileReputationEngine's
    /// single-stream decompressor). This inspector NEVER extracts to disk, NEVER reads an
    /// unbounded amount, and NEVER recurses without a depth budget - so a decompression bomb
    /// cannot exhaust memory or wall-clock here. When any cap is hit we STOP and report what
    /// we saw (fail closed: a container we could not fully vet is treated as more suspicious,
    /// not less). This is a CONTENT signal only - per Sentinel's constraints a filename or
    /// container shape must never self-authorize a kill; callers surface it as an observe-tier
    /// signal that seeds correlation.
    /// </summary>
    internal static class ArchiveContentInspector
    {
        // ---- Fail-closed resource caps (a zip bomb must never blow past these) --------------
        /// <summary>Largest container we will even open. Bigger files are hashed/scored, not walked.</summary>
        private const long MaxContainerBytes = 512L * 1024 * 1024; // 512 MB

        /// <summary>Max cumulative uncompressed bytes we will read across ALL entries + nesting.</summary>
        private const long MaxTotalDecompressedBytes = 512L * 1024 * 1024; // 512 MB

        /// <summary>Max entries we will enumerate before we stop (entry-count bomb guard).</summary>
        private const int MaxEntries = 4096;

        /// <summary>Max nesting depth (archive-in-archive) we will descend.</summary>
        private const int MaxDepth = 3;

        /// <summary>Bytes read per entry when sniffing magic / ratio (we never read a whole member).</summary>
        private const int EntrySniffBytes = 4096;

        /// <summary>Wall-clock budget for the entire inspection - bomb-safe hard stop.</summary>
        private static readonly TimeSpan TimeBudget = TimeSpan.FromSeconds(8);

        /// <summary>
        /// A per-entry compressed:uncompressed ratio at or above this is bomb-shaped.
        /// (The classic 42.zip layers hit ratios in the thousands; benign zips rarely exceed ~100.)
        /// </summary>
        private const double BombRatioThreshold = 1000.0;

        /// <summary>Overall container ratio (total uncompressed / container size) that is bomb-shaped.</summary>
        private const double BombOverallRatioThreshold = 250.0;

        private static readonly byte[] ZipMagic = { 0x50, 0x4B, 0x03, 0x04 };   // PK\x03\x04
        private static readonly byte[] ZipEmptyMagic = { 0x50, 0x4B, 0x05, 0x06 }; // empty archive EOCD
        private static readonly byte[] GzipMagic = { 0x1F, 0x8B };
        private static readonly byte[] SevenZipMagic = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C };
        private static readonly byte[] RarMagic = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 };

        // Scripting-host / LOLScript members that detonate without being a PE.
        private static readonly string[] ScriptExtensions =
        {
            ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".ps1",
            ".bat", ".cmd", ".lnk", ".scf", ".url", ".chm", ".hlp", ".vba",
        };

        private static readonly string[] ArchiveExtensions =
        {
            ".zip", ".jar", ".apk", ".xpi", ".vsix", ".nupkg", ".appx", ".7z",
            ".rar", ".cab", ".gz", ".tgz", ".bz2", ".xz", ".iso", ".img",
        };

        /// <summary>
        /// Inspect a container file. Returns a populated <see cref="ArchiveContentAnalysis"/>.
        /// Never throws - any failure yields <see cref="ArchiveContentAnalysis.InspectionAborted"/>
        /// set true (fail closed) with whatever partial findings were gathered.
        /// </summary>
        public static ArchiveContentAnalysis Inspect(string filePath)
        {
            var result = new ArchiveContentAnalysis();
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists) return result;
                result.ContainerBytes = fi.Length;

                if (fi.Length <= 0 || fi.Length > MaxContainerBytes)
                {
                    // Too big to vet safely - fail closed (we could not rule out a bomb).
                    result.InspectionAborted = fi.Length > MaxContainerBytes;
                    return result;
                }

                var ext = Path.GetExtension(filePath);
                var deadline = DateTime.UtcNow + TimeBudget;
                var budget = new WalkBudget(deadline);

                if (IsIsoOrImg(ext))
                {
                    result.IsDiskImage = true;
                    InspectDiskImage(filePath, result, budget);
                }
                else
                {
                    // Treat everything else openable-as-zip as a zip family container.
                    InspectZip(filePath, result, budget, depth: 0);
                }

                FinalizeVerdict(result);
            }
            catch
            {
                // Fail closed: a container we could not parse is treated as un-vetted.
                result.InspectionAborted = true;
            }
            return result;
        }

        private static bool IsIsoOrImg(string ext) =>
            ext.Equals(".iso", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".img", StringComparison.OrdinalIgnoreCase);

        // -------------------------------------------------------------------------------------
        // ZIP-family inspection (bounded ZipArchive entry walk, no extraction to disk)
        // -------------------------------------------------------------------------------------
        private static void InspectZip(string filePath, ArchiveContentAnalysis result, WalkBudget budget, int depth)
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            InspectZipStream(fs, result, budget, depth);
        }

        private static void InspectZipStream(Stream stream, ArchiveContentAnalysis result, WalkBudget budget, int depth)
        {
            if (depth > MaxDepth)
            {
                result.NestedDepthExceeded = true;
                result.MaxNestingDepth = Math.Max(result.MaxNestingDepth, depth);
                return;
            }
            result.MaxNestingDepth = Math.Max(result.MaxNestingDepth, depth);

            ZipArchive archive;
            try
            {
                archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
            }
            catch
            {
                // Not a readable zip at this layer - nothing more to do here.
                return;
            }

            using (archive)
            {
                foreach (var entry in archive.Entries)
                {
                    if (budget.Expired) { result.InspectionAborted = true; return; }
                    if (result.EntryCount >= MaxEntries) { result.EntryCountExceeded = true; return; }

                    result.EntryCount++;

                    long declared = entry.Length;          // uncompressed size from central directory
                    long compressed = entry.CompressedLength;

                    // Track declared totals against the container budget (bomb by declared size).
                    result.DeclaredUncompressedBytes += Math.Max(0, declared);

                    // Per-entry declared ratio (cheap, no read): classic layered-bomb signal.
                    if (compressed > 0 && declared > 0)
                    {
                        double ratio = (double)declared / compressed;
                        if (ratio > result.MaxEntryRatio) result.MaxEntryRatio = ratio;
                        if (ratio >= BombRatioThreshold) result.ZipBombShape = true;
                    }

                    // Guard: if declared totals alone already look explosive, flag and stop reading bodies.
                    if (result.DeclaredUncompressedBytes > MaxTotalDecompressedBytes)
                    {
                        result.ZipBombShape = true;
                        result.InspectionAborted = true;
                        return;
                    }

                    var entryName = entry.FullName ?? entry.Name ?? "";
                    var entryExt = Path.GetExtension(entryName);

                    bool looksArchive = HasArchiveExtension(entryExt);
                    bool looksScript = HasScriptExtension(entryExt);

                    // Sniff a bounded prefix of the entry body to classify by magic bytes and to
                    // measure ACTUAL decompressed bytes read (defends against a lying central dir).
                    byte[] head = ReadEntryPrefix(entry, budget, result);
                    if (head.Length > 0)
                    {
                        if (IsPe(head)) result.ContainsExecutable = true;
                        if (IsZip(head) || IsGzip(head) || IsSevenZip(head) || IsRar(head))
                            looksArchive = true;
                    }
                    if (looksScript) result.ContainsScriptHost = true;

                    // Descend into a nested archive entry (depth-budgeted, still no disk extraction).
                    if (looksArchive && depth < MaxDepth)
                    {
                        result.ContainsNestedArchive = true;
                        if (budget.Expired) { result.InspectionAborted = true; return; }
                        try
                        {
                            // Copy the nested entry into a bounded MemoryStream, then recurse.
                            using var nested = CopyEntryBounded(entry, budget, result);
                            if (nested != null)
                            {
                                nested.Position = 0;
                                // Only ZIP-family nesting is descended structurally; gzip/7z/rar
                                // are flagged as nested-archive but not unpacked (out of scope,
                                // and unpacking them safely needs external libs we don't ship).
                                if (IsLikelyZip(nested))
                                    InspectZipStream(nested, result, budget, depth + 1);
                            }
                        }
                        catch
                        {
                            result.InspectionAborted = true;
                        }
                    }
                    else if (looksArchive)
                    {
                        result.ContainsNestedArchive = true;
                        result.NestedDepthExceeded = true;
                    }
                }
            }
        }

        /// <summary>
        /// Read up to <see cref="EntrySniffBytes"/> from an entry body, counting the bytes actually
        /// decompressed against the global budget. Returns the prefix (possibly shorter). Fail-closed.
        /// </summary>
        private static byte[] ReadEntryPrefix(ZipArchiveEntry entry, WalkBudget budget, ArchiveContentAnalysis result)
        {
            try
            {
                using var es = entry.Open();
                var buf = new byte[EntrySniffBytes];
                int total = 0, n;
                while (total < buf.Length &&
                       (n = es.Read(buf, total, buf.Length - total)) > 0)
                {
                    total += n;
                    result.ActualDecompressedBytes += n;
                    if (result.ActualDecompressedBytes > MaxTotalDecompressedBytes)
                    {
                        result.ZipBombShape = true;
                        result.InspectionAborted = true;
                        break;
                    }
                    if (budget.Expired) { result.InspectionAborted = true; break; }
                }
                if (total == buf.Length) return buf;
                var trimmed = new byte[total];
                Buffer.BlockCopy(buf, 0, trimmed, 0, total);
                return trimmed;
            }
            catch
            {
                result.InspectionAborted = true;
                return Array.Empty<byte>();
            }
        }

        /// <summary>
        /// Copy a nested archive entry into memory, hard-capped. If the entry decompresses past
        /// the remaining budget we abort (bomb) and return null. Never allocates unbounded.
        /// </summary>
        private static MemoryStream? CopyEntryBounded(ZipArchiveEntry entry, WalkBudget budget, ArchiveContentAnalysis result)
        {
            // Cap a single nested member copy to 64 MB regardless of declared size.
            const int PerNestedCap = 64 * 1024 * 1024;
            var ms = new MemoryStream();
            try
            {
                using var es = entry.Open();
                var buf = new byte[81920];
                int n;
                while ((n = es.Read(buf, 0, buf.Length)) > 0)
                {
                    ms.Write(buf, 0, n);
                    result.ActualDecompressedBytes += n;
                    if (ms.Length > PerNestedCap ||
                        result.ActualDecompressedBytes > MaxTotalDecompressedBytes)
                    {
                        result.ZipBombShape = true;
                        result.InspectionAborted = true;
                        ms.Dispose();
                        return null;
                    }
                    if (budget.Expired)
                    {
                        result.InspectionAborted = true;
                        ms.Dispose();
                        return null;
                    }
                }
                return ms;
            }
            catch
            {
                ms.Dispose();
                result.InspectionAborted = true;
                return null;
            }
        }

        // -------------------------------------------------------------------------------------
        // Disk-image (ISO / IMG) shallow inspection - we do NOT mount. We scan a bounded prefix
        // of the raw image for embedded container/PE/script magic. This is deliberately shallow:
        // full ISO9660/UDF filesystem walking is out of scope and risky, so we fail closed and
        // treat an image carrying archive/PE magic as suspicious content worth an observe signal.
        // -------------------------------------------------------------------------------------
        private static void InspectDiskImage(string filePath, ArchiveContentAnalysis result, WalkBudget budget)
        {
            const int MaxImageScanBytes = 32 * 1024 * 1024; // scan first 32 MB of the image
            const int ChunkSize = 1 * 1024 * 1024;
            const int Overlap = 16;
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                long toScan = Math.Min(MaxImageScanBytes, fs.Length);
                var buf = new byte[ChunkSize + Overlap];
                long scanned = 0;
                int carry = 0;
                while (scanned < toScan)
                {
                    if (budget.Expired) { result.InspectionAborted = true; return; }
                    int want = (int)Math.Min(ChunkSize, toScan - scanned);
                    int read = fs.Read(buf, carry, want);
                    if (read <= 0) break;
                    int windowLen = carry + read;

                    if (ContainsMagic(buf, windowLen, ZipMagic) ||
                        ContainsMagic(buf, windowLen, SevenZipMagic) ||
                        ContainsMagic(buf, windowLen, RarMagic))
                    {
                        result.ContainsNestedArchive = true;
                    }
                    if (ContainsMagic(buf, windowLen, GzipMagic))
                        result.ContainsNestedArchive = true;
                    if (ContainsPeHeader(buf, windowLen))
                        result.ContainsExecutable = true;

                    scanned += read;
                    // preserve a small overlap so magic straddling a chunk boundary is still found
                    if (windowLen >= Overlap)
                    {
                        Buffer.BlockCopy(buf, windowLen - Overlap, buf, 0, Overlap);
                        carry = Overlap;
                    }
                    else carry = 0;

                    if (read < want) break;
                }
            }
            catch
            {
                result.InspectionAborted = true;
            }
        }

        private static void FinalizeVerdict(ArchiveContentAnalysis result)
        {
            // Overall container ratio (declared vs container size) - bomb-shaped if huge.
            if (result.ContainerBytes > 0 && result.DeclaredUncompressedBytes > 0)
            {
                result.OverallRatio = (double)result.DeclaredUncompressedBytes / result.ContainerBytes;
                if (result.OverallRatio >= BombOverallRatioThreshold)
                    result.ZipBombShape = true;
            }
            result.Inspected = result.EntryCount > 0 || result.IsDiskImage;
        }

        // ---- magic-byte helpers -------------------------------------------------------------
        private static bool HasArchiveExtension(string ext)
        {
            foreach (var a in ArchiveExtensions)
                if (ext.Equals(a, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool HasScriptExtension(string ext)
        {
            foreach (var s in ScriptExtensions)
                if (ext.Equals(s, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool IsPe(byte[] head) => head.Length >= 2 && head[0] == 0x4D && head[1] == 0x5A; // MZ
        private static bool IsZip(byte[] head) => StartsWith(head, ZipMagic) || StartsWith(head, ZipEmptyMagic);
        private static bool IsGzip(byte[] head) => head.Length >= 3 && head[0] == GzipMagic[0] && head[1] == GzipMagic[1] && head[2] == 0x08;
        private static bool IsSevenZip(byte[] head) => StartsWith(head, SevenZipMagic);
        private static bool IsRar(byte[] head) => StartsWith(head, RarMagic);

        private static bool IsLikelyZip(Stream s)
        {
            try
            {
                long pos = s.Position;
                var sig = new byte[4];
                int n = s.Read(sig, 0, 4);
                s.Position = pos;
                return n == 4 && (StartsWith(sig, ZipMagic) || StartsWith(sig, ZipEmptyMagic));
            }
            catch { return false; }
        }

        private static bool StartsWith(byte[] data, byte[] prefix)
        {
            if (data.Length < prefix.Length) return false;
            for (int i = 0; i < prefix.Length; i++)
                if (data[i] != prefix[i]) return false;
            return true;
        }

        private static bool ContainsMagic(byte[] data, int len, byte[] magic)
        {
            int end = len - magic.Length;
            for (int i = 0; i <= end; i++)
            {
                int j = 0;
                while (j < magic.Length && data[i + j] == magic[j]) j++;
                if (j == magic.Length) return true;
            }
            return false;
        }

        /// <summary>
        /// Detect a plausible PE embedded in a raw image: an 'MZ' followed (within the DOS stub
        /// reach we can see in this window) by a 'PE\0\0' signature. We only confirm the MZ+PE
        /// pair inside the scanned window to avoid flagging the ubiquitous 'MZ' bigram.
        /// </summary>
        private static bool ContainsPeHeader(byte[] data, int len)
        {
            for (int i = 0; i + 1 < len; i++)
            {
                if (data[i] != 0x4D || data[i + 1] != 0x5A) continue; // 'MZ'
                int scanEnd = Math.Min(len - 4, i + 1024);
                for (int j = i + 2; j <= scanEnd; j++)
                {
                    if (data[j] == 0x50 && data[j + 1] == 0x45 &&
                        data[j + 2] == 0x00 && data[j + 3] == 0x00) // 'PE\0\0'
                        return true;
                }
            }
            return false;
        }

        private sealed class WalkBudget
        {
            private readonly DateTime _deadline;
            public WalkBudget(DateTime deadline) => _deadline = deadline;
            public bool Expired => DateTime.UtcNow >= _deadline;
        }
    }

    /// <summary>
    /// Findings from a bounded archive/disk-image content inspection. All numeric fields are
    /// capped by the inspector's fail-closed budgets. This is a CONTENT signal - it may seed
    /// correlation but must never solo-authorize a destructive response (Sentinel constraints:
    /// a container shape / filename an attacker controls is not kill authority).
    /// </summary>
    public sealed class ArchiveContentAnalysis
    {
        /// <summary>True once the inspector actually walked entries or scanned an image.</summary>
        public bool Inspected { get; set; }

        /// <summary>True when the container is an ISO/IMG disk image (shallow-scanned, not mounted).</summary>
        public bool IsDiskImage { get; set; }

        /// <summary>Inspection stopped early against a fail-closed cap (treat as un-vetted / suspicious).</summary>
        public bool InspectionAborted { get; set; }

        public int EntryCount { get; set; }
        public bool EntryCountExceeded { get; set; }

        public int MaxNestingDepth { get; set; }
        public bool NestedDepthExceeded { get; set; }
        public bool ContainsNestedArchive { get; set; }

        /// <summary>A PE (MZ/PE) payload was found inside the container.</summary>
        public bool ContainsExecutable { get; set; }

        /// <summary>A scripting-host member (.hta/.js/.vbs/.ps1/.lnk/...) was found inside.</summary>
        public bool ContainsScriptHost { get; set; }

        /// <summary>Container exhibits decompression-bomb shape (ratio / declared-size explosion).</summary>
        public bool ZipBombShape { get; set; }

        public long ContainerBytes { get; set; }
        public long DeclaredUncompressedBytes { get; set; }
        public long ActualDecompressedBytes { get; set; }
        public double MaxEntryRatio { get; set; }
        public double OverallRatio { get; set; }

        /// <summary>True when any content-smuggling shape was found (used by scoring/emit).</summary>
        public bool HasSmugglingSignal =>
            ZipBombShape || ContainsNestedArchive || ContainsExecutable || ContainsScriptHost || NestedDepthExceeded;

        /// <summary>Short human-readable summary for evidence text.</summary>
        public string Describe()
        {
            var parts = new List<string>();
            if (ZipBombShape) parts.Add($"zip-bomb shape (maxEntryRatio={MaxEntryRatio:F0}, overallRatio={OverallRatio:F0})");
            if (ContainsExecutable) parts.Add("embedded executable (PE)");
            if (ContainsScriptHost) parts.Add("embedded script-host member");
            if (ContainsNestedArchive) parts.Add($"nested archive (depth={MaxNestingDepth})");
            if (NestedDepthExceeded) parts.Add("nesting depth cap exceeded");
            if (EntryCountExceeded) parts.Add("entry-count cap exceeded");
            if (InspectionAborted) parts.Add("inspection aborted at fail-closed cap");
            if (parts.Count == 0) parts.Add("no smuggling signal");
            return string.Join("; ", parts);
        }
    }
}
