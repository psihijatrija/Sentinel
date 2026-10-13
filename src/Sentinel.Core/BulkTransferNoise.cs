using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Legitimate high-upload workloads (torrent seeding, P2P, sync mirrors, download managers)
    /// that must not be treated as data-exfiltration terminal fuel.
    ///
    /// Product law: observe bulk user traffic; only chain-confirmed malice (cred dump, C2,
    /// ransomware encryption, reverse shell, token theft, true exfil chains) may act.
    /// v1.9.9
    /// </summary>
    public static class BulkTransferNoise
    {
        /// <summary>
        /// Process name stems (no .exe) that commonly generate sustained outbound volume
        /// without being malware. Name match only - not a trust grant for other rules.
        /// </summary>
        public static readonly HashSet<string> ProcessNameStems = new(StringComparer.OrdinalIgnoreCase)
        {
            // BitTorrent / P2P clients
            "qbittorrent", "qbittorrent-nox",
            "utorrent", "utorrentie", "bittorrent",
            "transmission-qt", "transmission-gtk", "transmission-daemon", "transmission",
            "deluge", "deluged", "deluge-gtk",
            "tixati", "biglybt", "vuze", "azureus",
            "frostwire", "tribler", "picoTorrent", "picotorrent",
            "webtorrent", "webtorrent-desktop",
            "rtorrent", "ktorrent", "fragments",
            // aria2 / multi-protocol downloaders often used for ISO mirrors (UUP, etc.)
            "aria2c", "aria2",
            // Usenet
            "sabnzbd", "nzbget", "nzbget-server",
            // Large legitimate sync / mirror tools (volume only - other monitors still watch)
            "freefileync", "resync",
            // Game / content delivery that can seed or upload heavily
            "steam", "steamwebhelper", "steamservice",
            "EpicGamesLauncher", "EpicWebHelper",
            "Battle.net", "Agent", // Blizzard Agent - careful: too generic alone
        };

        // Overly generic stems that need path corroboration if we ever kill on them.
        // For volume-spike suppression we only use unambiguous client names.
        private static readonly HashSet<string> UnambiguousBulkClients = new(StringComparer.OrdinalIgnoreCase)
        {
            "qbittorrent", "qbittorrent-nox",
            "utorrent", "utorrentie", "bittorrent",
            "transmission-qt", "transmission-gtk", "transmission-daemon", "transmission",
            "deluge", "deluged", "deluge-gtk",
            "tixati", "biglybt", "vuze", "azureus",
            "frostwire", "tribler", "picotorrent",
            "webtorrent", "webtorrent-desktop",
            "rtorrent", "ktorrent", "fragments",
            "aria2c", "aria2",
            "sabnzbd", "nzbget", "nzbget-server",
            "freefileync",
        };

        /// <summary>
        /// True when process name (with or without .exe) looks like a known bulk-transfer client.
        /// </summary>
        public static bool IsBulkTransferProcessName(string? processName)
        {
            if (string.IsNullOrWhiteSpace(processName)) return false;
            var stem = processName!.Trim();
            if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                stem = stem.Substring(0, stem.Length - 4);
            return UnambiguousBulkClients.Contains(stem);
        }

        /// <summary>
        /// Enumerates running processes and returns true if any known bulk-transfer client is alive.
        /// Fail-open (returns false) on enumeration errors so real exfil spikes are not lost forever.
        /// </summary>
        public static bool IsAnyBulkTransferProcessRunning(out string? matchedProcessName)
        {
            matchedProcessName = null;
            try
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        var name = p.ProcessName;
                        if (IsBulkTransferProcessName(name))
                        {
                            matchedProcessName = name;
                            return true;
                        }
                    }
                    catch
                    {
                        // Access denied / exited mid-enum
                    }
                    finally
                    {
                        try { p.Dispose(); } catch { }
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        public static bool IsAnyBulkTransferProcessRunning()
            => IsAnyBulkTransferProcessRunning(out _);
    }
}
