using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;

namespace Sentinel.Core
{
    /// <summary>
    /// Lightweight "already-scanned" index for <see cref="FileVerdictScanner"/>.
    ///
    /// PROBLEM this solves: the verdict cache (<see cref="FileVerdictAds"/>) is keyed by the
    /// file's SHA256. That means the only way to ask "have I already scanned this file?" was to
    /// first read the ENTIRE file and hash it - so every background drive walk re-read and
    /// re-hashed every executable on every fixed volume, producing sustained 18-50 MB/s of HDD
    /// churn even when nothing had changed.
    ///
    /// This index lets the scanner answer that question from cheap file metadata (size +
    /// last-write time) with NO file read at all. A file is considered already-scanned when its
    /// path is present AND its current size and last-write-time tick match the recorded values.
    /// Any content change necessarily bumps size and/or mtime, which invalidates the entry and
    /// forces a fresh hash + reputation evaluation - so correctness is preserved.
    ///
    /// The index is advisory and fail-open: if it is missing, corrupt, or unreadable the scanner
    /// simply falls back to hashing (its previous behavior). It is never used for a security
    /// decision - only to decide whether the expensive read can be skipped - so it is deliberately
    /// NOT signed (unlike verdict payloads).
    ///
    /// Persistence: a single compact text file under ProgramData\Sentinel\Secure, one entry per
    /// line as "size|mtimeTicks|path". Writes are batched (flushed on a timer / on dispose), never
    /// per-file, to avoid re-introducing write amplification.
    /// </summary>
    public sealed class FileScanIndex : IDisposable
    {
        private readonly string _indexPath;
        private readonly ConcurrentDictionary<string, (long Size, long MtimeTicks)> _entries =
            new(StringComparer.OrdinalIgnoreCase);

        private long _dirtyCount;
        private readonly System.Threading.Timer? _flushTimer;
        private readonly object _flushLock = new();
        private volatile bool _disposed;

        // Flush cadence for the batched writer. Small files, infrequent writes.
        private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(60);
        // Only rewrite the on-disk index when at least this many new entries have accumulated,
        // or on dispose. Keeps the walk from triggering repeated full-file rewrites.
        private const long FlushThreshold = 200;

        public FileScanIndex(string? secureDir = null)
        {
            string dir;
            if (!string.IsNullOrWhiteSpace(secureDir))
            {
                dir = secureDir!;
            }
            else
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                dir = Path.Combine(programData, "Sentinel", "Secure");
            }

            _indexPath = Path.Combine(dir, "scan_index.dat");

            try
            {
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
            }
            catch
            {
                // If we cannot create the directory the index just stays empty (fail-open).
            }

            Load();

            try
            {
                _flushTimer = new System.Threading.Timer(_ => TryFlush(force: false), null, FlushInterval, FlushInterval);
            }
            catch
            {
                _flushTimer = null;
            }
        }

        /// <summary>
        /// Returns true when this exact path was scanned before AND its current size and
        /// last-write-time still match what was recorded - i.e. the content is unchanged and the
        /// expensive hash can be skipped. Returns false (scan needed) on any mismatch, missing
        /// entry, or stat failure.
        /// </summary>
        public bool IsUnchangedSinceScan(string filePath)
        {
            if (string.IsNullOrEmpty(filePath))
                return false;
            if (!_entries.TryGetValue(filePath, out var recorded))
                return false;

            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists)
                    return false;
                return fi.Length == recorded.Size &&
                       fi.LastWriteTimeUtc.Ticks == recorded.MtimeTicks;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Record that this path has been scanned at its current size / last-write-time. Cheap:
        /// updates the in-memory map and marks the index dirty; the actual disk write is batched.
        /// </summary>
        public void MarkScanned(string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || _disposed)
                return;
            try
            {
                var fi = new FileInfo(filePath);
                if (!fi.Exists)
                    return;
                var key = fi.FullName;
                var value = (fi.Length, fi.LastWriteTimeUtc.Ticks);
                _entries[key] = value;

                if (Interlocked.Increment(ref _dirtyCount) >= FlushThreshold)
                    TryFlush(force: false);
            }
            catch
            {
                // best-effort - skipping the mark just means we re-hash next time
            }
        }

        private void Load()
        {
            try
            {
                if (!File.Exists(_indexPath))
                    return;

                foreach (var line in File.ReadLines(_indexPath, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;
                    // Format: size|mtimeTicks|path   (path may itself contain no '\n'; '|' in a
                    // Windows path is impossible, so a 3-way split on the first two separators is safe)
                    var firstSep = line.IndexOf('|');
                    if (firstSep <= 0)
                        continue;
                    var secondSep = line.IndexOf('|', firstSep + 1);
                    if (secondSep <= firstSep)
                        continue;

                    var sizeStr = line.Substring(0, firstSep);
                    var mtimeStr = line.Substring(firstSep + 1, secondSep - firstSep - 1);
                    var path = line.Substring(secondSep + 1);

                    if (long.TryParse(sizeStr, out var size) &&
                        long.TryParse(mtimeStr, out var mtime) &&
                        !string.IsNullOrEmpty(path))
                    {
                        _entries[path] = (size, mtime);
                    }
                }
            }
            catch
            {
                // Corrupt / unreadable index - start empty (fail-open, scanner re-hashes).
                _entries.Clear();
            }
        }

        /// <summary>
        /// Persist the current in-memory index to disk (atomic write-then-replace). Batched;
        /// callers do not need to invoke this directly under normal operation.
        /// </summary>
        public void TryFlush(bool force)
        {
            if (_disposed && !force)
                return;
            if (!force && Interlocked.Read(ref _dirtyCount) == 0)
                return;

            lock (_flushLock)
            {
                try
                {
                    var sb = new StringBuilder(_entries.Count * 64);
                    foreach (var kvp in _entries)
                    {
                        sb.Append(kvp.Value.Size).Append('|')
                          .Append(kvp.Value.MtimeTicks).Append('|')
                          .Append(kvp.Key).Append('\n');
                    }

                    var tmp = _indexPath + ".tmp";
                    File.WriteAllText(tmp, sb.ToString(), Encoding.UTF8);

                    // Atomic replace where possible; fall back to copy on failure.
                    try
                    {
                        if (File.Exists(_indexPath))
                            File.Replace(tmp, _indexPath, null);
                        else
                            File.Move(tmp, _indexPath);
                    }
                    catch
                    {
                        File.Copy(tmp, _indexPath, overwrite: true);
                        try { File.Delete(tmp); } catch { }
                    }

                    Interlocked.Exchange(ref _dirtyCount, 0);
                }
                catch
                {
                    // best-effort persistence - in-memory state still valid for this run
                }
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            _disposed = true;
            try { _flushTimer?.Dispose(); } catch { }
            TryFlush(force: true);
        }
    }
}
