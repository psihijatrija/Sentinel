using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace NanoAV
{
    // Known-files cache backed by a flat file: "sha256,true|false,timestamp".
    // Mirrors Load-Database / SNanoAVe-ToDatabase and the eviction cap.
    internal static class Database
    {
        private static readonly object Lock = new object();
        private static readonly Dictionary<string, bool> KnownFilesCache =
            new Dictionary<string, bool>();
        private static readonly Regex LineRegex =
            new Regex(@"^([0-9a-f]{64}),(true|false),(.+)$", RegexOptions.IgnoreCase);

        public static bool TryGet(string hash, out bool isSafe)
        {
            lock (Lock) { return KnownFilesCache.TryGetValue(hash, out isSafe); }
        }

        public static void Load()
        {
            lock (Lock)
            {
                if (File.Exists(Config.DatabaseFile))
                {
                    try
                    {
                        int count = 0;
                        foreach (string line in File.ReadAllLines(Config.DatabaseFile))
                        {
                            Match m = LineRegex.Match(line);
                            if (!m.Success) continue;

                            string hash = m.Groups[1].Value.ToLowerInvariant();
                            bool safe = bool.Parse(m.Groups[2].Value);
                            string ts = m.Groups[3].Value;

                            DateTime entryDate;
                            if (DateTime.TryParse(ts, CultureInfo.CurrentCulture,
                                    DateTimeStyles.None, out entryDate))
                            {
                                if (entryDate < DateTime.Now.AddDays(-Config.DatabaseCleanupDays))
                                    continue;
                            }

                            KnownFilesCache[hash] = safe;
                            count++;
                            if (count >= Config.MaxDatabaseEntries) break;
                        }
                        Logger.Log("Loaded " + count + " entries from database");
                    }
                    catch (Exception ex)
                    {
                        Logger.Log("Failed to load database: " + ex.Message);
                        KnownFilesCache.Clear();
                    }
                }
                else
                {
                    try { File.Create(Config.DatabaseFile).Dispose(); } catch { }
                    Logger.Log("Created new database file");
                }
            }
        }

        public static void SNanoAVe(string hash, bool isSafe)
        {
            if (string.IsNullOrEmpty(hash)) return;

            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string entry = hash + "," + (isSafe ? "True" : "False") + "," + timestamp;

            lock (Lock)
            {
                try
                {
                    File.AppendAllText(Config.DatabaseFile, entry + Environment.NewLine,
                        new UTF8Encoding(false));
                    KnownFilesCache[hash] = isSafe;
                }
                catch (Exception ex)
                {
                    Logger.Log("Failed to sNanoAVe to database: " + ex.Message);
                }

                // Hard cap: evict oldest ~10% when over the cap.
                if (KnownFilesCache.Count > Config.MaxDatabaseEntries)
                {
                    int evictCount = (int)(Config.MaxDatabaseEntries * 0.1);
                    var toEvict = new List<string>();
                    foreach (string k in KnownFilesCache.Keys)
                    {
                        toEvict.Add(k);
                        if (toEvict.Count >= evictCount) break;
                    }
                    foreach (string k in toEvict) KnownFilesCache.Remove(k);
                    Logger.Log("KnownFilesCache trimmed by " + toEvict.Count +
                        " entries (cap: " + Config.MaxDatabaseEntries + ")");
                }
            }
        }
    }
}
