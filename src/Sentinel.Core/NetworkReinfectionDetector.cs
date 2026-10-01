using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects processes that spawn within seconds of a network interface coming up,
    /// with no legitimate user-initiated parent chain. This catches the pattern where
    /// an infected router or LAN device pushes malware back to the machine via SMB,
    /// UPnP, or other protocols immediately upon reconnection.
    ///
    /// The attack pattern:
    /// 1. User cleans malware from disk
    /// 2. Machine reconnects to network (NIC up, WiFi reconnect, VPN reconnect)
    /// 3. Infected router/device pushes payload via SMB/UPnP within 1-10 seconds
    /// 4. New process spawns from temp/downloads/recycle with no explorer/user parent
    ///
    /// Detection: Flag any new process that starts within 15 seconds of NIC-up event
    /// AND runs from a suspicious path AND has no user-interactive parent chain.
    /// </summary>
    public sealed class NetworkReinfectionDetector : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ProcessAncestryCache _ancestryCache;
        private readonly ILogger<NetworkReinfectionDetector> _logger;

        private readonly SignerTrustService? _signerTrust;

        // Track NIC up events
        private readonly ConcurrentDictionary<string, DateTime> _nicUpEvents = new();

        // Track alerted PIDs to avoid duplicates
        private readonly ConcurrentDictionary<int, DateTime> _alertedPids = new();

        // How long after NIC-up to consider a process suspicious (seconds)
        private const int NicUpWindowSeconds = 15;

        // Known user-interactive parent processes (legitimate launch sources)
        private static readonly HashSet<string> UserInteractiveParents = new(StringComparer.OrdinalIgnoreCase)
        {
            "explorer", "explorer.exe",
            "userinit", "userinit.exe",
            "winlogon", "winlogon.exe",
            "dwm", "dwm.exe",
            "sihost", "sihost.exe",
            "taskmgr", "taskmgr.exe",
            "cmd", "cmd.exe",
            "powershell", "powershell.exe",
            "pwsh", "pwsh.exe",
            "WindowsTerminal", "WindowsTerminal.exe",
        };

        // Suspicious paths where router-pushed malware typically lands
        private static readonly string[] SuspiciousPaths = new[]
        {
            @"\$Recycle.Bin\",
            @"\Temp\",
            @"\tmp\",
            @"\AppData\Local\Temp\",
            @"\Downloads\",
            @"\Users\Public\",
            @"\ProgramData\",
            @"\Windows\Temp\",
        };

        public NetworkReinfectionDetector(
            DetectionEngine detectionEngine,
            ProcessAncestryCache ancestryCache,
            ILogger<NetworkReinfectionDetector> logger,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = detectionEngine;
            _ancestryCache = ancestryCache;
            _logger = logger;
            _signerTrust = signerTrust;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NetworkReinfectionDetector] Started - monitoring NIC state changes");

            // Register for network change events
            NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;
            NetworkChange.NetworkAddressChanged += OnNetworkAddressChanged;

            // Capture initial NIC states
            var initialNics = new HashSet<string>();
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus == OperationalStatus.Up)
                    initialNics.Add(nic.Id);
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(5000, ct); // Check every 5 seconds

                    // Detect NIC status changes by polling (backup for event-based detection)
                    foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        if (nic.OperationalStatus == OperationalStatus.Up)
                        {
                            if (!initialNics.Contains(nic.Id))
                            {
                                // NIC came up since last check
                                _nicUpEvents[nic.Id] = DateTime.UtcNow;
                                initialNics.Add(nic.Id);
                                _logger.LogInformation("[NetworkReinfectionDetector] NIC up: {Name} ({Id})",
                                    nic.Name, nic.Id);
                            }
                        }
                        else
                        {
                            initialNics.Remove(nic.Id);
                        }
                    }

                    // Check if any NIC came up recently
                    var recentNicUp = _nicUpEvents.Values
                        .Any(t => DateTime.UtcNow - t < TimeSpan.FromSeconds(NicUpWindowSeconds));

                    if (!recentNicUp) continue;

                    // Scan for suspicious new processes that started within the window
                    await ScanForSuspiciousSpawnsAsync(ct);

                    // Prune old NIC events (older than 30 seconds)
                    var cutoff = DateTime.UtcNow.AddSeconds(-30);
                    foreach (var kvp in _nicUpEvents)
                    {
                        if (kvp.Value < cutoff)
                            _nicUpEvents.TryRemove(kvp.Key, out _);
                    }

                    // Prune old alerted PIDs
                    foreach (var kvp in _alertedPids)
                    {
                        if (kvp.Value < cutoff)
                            _alertedPids.TryRemove(kvp.Key, out _);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NetworkReinfectionDetector] Error"); }
            }

            NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;
            NetworkChange.NetworkAddressChanged -= OnNetworkAddressChanged;
        }

        private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
        {
            if (e.IsAvailable)
            {
                // Network became available - record as a NIC-up event
                _nicUpEvents["availability_event"] = DateTime.UtcNow;
                _logger.LogInformation("[NetworkReinfectionDetector] Network availability changed: UP");
            }
        }

        private void OnNetworkAddressChanged(object? sender, EventArgs e)
        {
            // Address change often indicates reconnection (DHCP lease, VPN connect)
            _nicUpEvents["address_change"] = DateTime.UtcNow;
        }

        private async Task ScanForSuspiciousSpawnsAsync(CancellationToken ct)
        {
            var now = DateTime.UtcNow;
            var earliestNicUp = _nicUpEvents.Values.Min();

            foreach (var proc in Process.GetProcesses())
            {
                if (ct.IsCancellationRequested) break;
                try
                {
                    if (proc.Id <= 4) continue;
                    if (_alertedPids.ContainsKey(proc.Id)) continue;

                    DateTime startTime;
                    try { startTime = proc.StartTime.ToUniversalTime(); }
                    catch { continue; }

                    // Only consider processes that started AFTER the NIC came up and within the window
                    if (startTime < earliestNicUp) continue;
                    if (now - startTime > TimeSpan.FromSeconds(NicUpWindowSeconds)) continue;

                    // Get image path
                    string? imagePath = null;
                    try { imagePath = SecurityValidation.GetProcessImagePath(proc.Id); } catch { }
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    // Must be from a suspicious path
                    if (!IsSuspiciousPath(imagePath!)) continue;

                    // Skip if the binary is signed by a trusted publisher (e.g. GoogleUpdate, BraveUpdate)
                    if (_signerTrust != null && _signerTrust.IsSignedFile(imagePath!))
                        continue;

                    // Check parent chain - if parent is user-interactive, skip
                    if (HasUserInteractiveParent(proc.Id)) continue;

                    // This is suspicious: new process from suspicious path, started within
                    // seconds of NIC-up, with no user-interactive parent
                    _alertedPids[proc.Id] = now;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Network Reinfection: Process Spawned After NIC-Up Without User Parent",
                        Evidence = $"Process '{proc.ProcessName}' (PID {proc.Id}) started at {startTime:O} " +
                                   $"from '{imagePath}', {(startTime - earliestNicUp).TotalSeconds:F1}s after network reconnection. " +
                                   $"No user-interactive parent in ancestry chain.",
                        Reasoning = "A process spawned from a suspicious location (Temp, Recycle Bin, Public, Downloads) " +
                                    "within seconds of a network interface coming up, with no user-initiated parent process. " +
                                    "This pattern matches router/LAN-based reinfection where an infected network device " +
                                    "pushes malware via SMB, UPnP, or WPAD immediately upon detecting the machine reconnect. " +
                                    "The infection source is likely outside this machine (router, NAS, or another LAN host).",
                        Confidence = 0.85,
                        Tier = DetectionTier.Tier1Behavioral,
                        AuthorizedResponse = ResponseAction.KillProcessTree,
                        SignalType = SignalType.SecurityEvasion,
                        ProcessName = proc.ProcessName,
                        ProcessId = proc.Id,
                        Metadata = new Dictionary<string, string>
                        {
                            ["ImagePath"] = imagePath!,
                            ["ProcessStartTime"] = startTime.ToString("O"),
                            ["NicUpTime"] = earliestNicUp.ToString("O"),
                            ["DelayAfterNicUp"] = $"{(startTime - earliestNicUp).TotalSeconds:F1}s",
                            ["ReinfectionType"] = "NetworkPush"
                        }
                    });
                }
                catch { }
                finally { proc.Dispose(); }
            }
        }

        private bool HasUserInteractiveParent(int pid)
        {
            try
            {
                // Walk up to 5 levels of parent chain
                int currentPid = pid;
                for (int depth = 0; depth < 5; depth++)
                {
                    var (parentId, parentName) = _ancestryCache.GetParent(currentPid);
                    if (parentId <= 0) break;

                    if (UserInteractiveParents.Contains(parentName))
                        return true;

                    currentPid = parentId;
                    if (currentPid <= 4) break;
                }
            }
            catch { }
            return false;
        }

        private static bool IsSuspiciousPath(string path)
        {
            return SuspiciousPaths.Any(s => path.Contains(s));
        }
    }
}
