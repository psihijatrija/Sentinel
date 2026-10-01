using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    // 
    // Hardware Security Guard - monitors IOMMU/VT-d, Secure Boot, and BitLocker state
    // Detects disabled hardware security features that enable firmware/DMA attacks
    // 
    public sealed class HardwareSecurityGuard : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<HardwareSecurityGuard> _logger;

        // State-change dedup: these are static posture facts (BitLocker, Secure Boot, etc.) that
        // change rarely. Re-emitting them every 60s bloats the event log with thousands of
        // identical detections. Track the last-observed "bad" state per check and only emit a
        // detection on a transition into the bad state (or the first observation of it). When a
        // condition clears, the flag resets so a later regression re-alerts.
        // true  = currently in the bad/alerting state (already emitted)
        // false/absent = currently good (or not yet observed)
        private readonly System.Collections.Generic.Dictionary<string, bool> _lastBadState = new();

        public HardwareSecurityGuard(DetectionEngine de, SentinelConfig config, ILogger<HardwareSecurityGuard> l)
        {
            _detectionEngine = de; _config = config; _logger = l;
        }

        /// <summary>
        /// Returns true only when <paramref name="isBad"/> represents a NEW transition into the
        /// bad state for <paramref name="checkKey"/> (i.e. the caller should emit a detection).
        /// Repeated bad observations return false (suppressed). A good observation clears the
        /// latch so a future regression re-alerts.
        /// </summary>
        private bool ShouldEmit(string checkKey, bool isBad)
        {
            _lastBadState.TryGetValue(checkKey, out bool wasBad);
            _lastBadState[checkKey] = isBad;

            if (isBad && !wasBad)
            {
                return true; // good -> bad (or first-ever bad): alert once
            }
            if (!isBad && wasBad)
            {
                _logger.LogInformation("[HardwareSecurityGuard] {Check} recovered (now healthy)", checkKey);
            }
            return false; // still-bad (suppressed) or still-good (nothing to do)
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[HardwareSecurityGuard] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await CheckIommuAsync(ct);
                    await CheckSecureBootAsync();
                    await CheckBitLockerAsync(ct);
                    await CheckCredentialGuardAsync();
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[HardwareSecurityGuard] Error"); }
            }
        }

        private async Task CheckIommuAsync(CancellationToken ct)
        {
            try
            {
                bool vbsEnabled = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                    var val = key?.GetValue("EnableVirtualizationBasedSecurity");
                    vbsEnabled = val is int v && v == 1;
                }
                catch { }

                bool hypervisorAuto = false;
                try
                {
                    var psi = new ProcessStartInfo("bcdedit.exe", "/enum")
                    {
                        CreateNoWindow = true, UseShellExecute = false,
                        RedirectStandardOutput = true
                    };
                    using var proc = Process.Start(psi);
                    if (proc != null)
                    {
                        var output = await proc.StandardOutput.ReadToEndAsync();
                        proc.WaitForExit(5000);
                        hypervisorAuto = output.Contains("hypervisorlaunchtype")
                            && output.Contains("Auto");
                    }
                }
                catch { }

                if (ShouldEmit("IOMMU/VT-d", !vbsEnabled && !hypervisorAuto))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardware Security: IOMMU/VT-d Disabled",
                        Evidence = $"VBS registry={vbsEnabled}, hypervisorlaunchtype Auto={hypervisorAuto}",
                        Reasoning = "Both VBS (Virtualization-Based Security) and Hyper-V hypervisor are disabled. " +
                                    "IOMMU/VT-d protection is inactive, leaving the system vulnerable to DMA attacks " +
                                    "via Thunderbolt/PCIe and firmware-level memory manipulation.",
                        Confidence = 0.70, Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[HardwareSecurityGuard] IOMMU check error"); }
        }

        private async Task CheckSecureBootAsync()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                var val = key?.GetValue("UEFISecureBootEnabled");
                bool secureBootDisabled = val is int enabled && enabled == 0;
                if (ShouldEmit("SecureBoot", secureBootDisabled))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardware Security: Secure Boot Disabled",
                        Evidence = "UEFISecureBootEnabled=0 in registry",
                        Reasoning = "UEFI Secure Boot is disabled, allowing unsigned bootloaders and rootkits " +
                                    "to execute before the OS. Combined with disabled IOMMU, the system has no " +
                                    "hardware-level integrity guarantees.",
                        Confidence = 0.60, Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }
            }
            catch { }
        }

        private async Task CheckBitLockerAsync(CancellationToken ct)
        {
            try
            {
                bool bitlockerActive = false;

                // Try registry first
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\BitLocker\FixedDrives");
                    if (key != null)
                    {
                        var cDrive = key.GetValue("C:");
                        if (cDrive != null) bitlockerActive = true;
                    }
                }
                catch { }

                // Fallback: query manage-bde
                if (!bitlockerActive)
                {
                    try
                    {
                        var psi = new ProcessStartInfo("manage-bde.exe", "-status C:")
                        {
                            CreateNoWindow = true, UseShellExecute = false,
                            RedirectStandardOutput = true
                        };
                        using var proc = Process.Start(psi);
                        if (proc != null)
                        {
                            var output = await proc.StandardOutput.ReadToEndAsync();
                            proc.WaitForExit(5000);
                            // "Protection Status:    Protection On" or "Fully Encrypted"
                            bitlockerActive = output.Contains("Protection On")
                                || output.Contains("Fully Encrypted");
                        }
                    }
                    catch { }
                }

                if (ShouldEmit("BitLocker", !bitlockerActive))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardware Security: BitLocker Disabled on C:",
                        Evidence = "C: drive does not appear to have BitLocker encryption active",
                        Reasoning = "The system drive is not encrypted with BitLocker. An attacker with physical " +
                                    "access can boot from external media and read/modify all files, extract SAM " +
                                    "hashes, or plant bootkits without any resistance.",
                        Confidence = 0.55, Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[HardwareSecurityGuard] BitLocker check error"); }
        }

        private async Task CheckCredentialGuardAsync()
        {
            try
            {
                bool credGuardActive = false;

                // Check if LsaIso.exe is running (Credential Guard's isolated LSA process)
                var lsaIso = Process.GetProcessesByName("LsaIso");
                credGuardActive = lsaIso.Length > 0;
                foreach (var p in lsaIso) p.Dispose();

                if (!credGuardActive)
                {
                    // Check registry for VBS Credential Guard configuration
                    try
                    {
                        using var key = Registry.LocalMachine.OpenSubKey(
                            @"SYSTEM\CurrentControlSet\Control\Lsa");
                        var val = key?.GetValue("LsaCfgFlags");
                        if (val is int flags && flags > 0) credGuardActive = true;
                    }
                    catch { }
                }

                if (ShouldEmit("CredentialGuard", !credGuardActive))
                {
                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Hardware Security: Credential Guard Not Active",
                        Evidence = "LsaIso.exe not running and LsaCfgFlags not set. " +
                                   "Credential Guard (VBS-based LSA isolation) is not protecting credentials.",
                        Reasoning = "Without Credential Guard, NTLM hashes, Kerberos tickets, and domain credentials " +
                                    "reside in standard LSASS memory and can be extracted by tools like Mimikatz. " +
                                    "Enabling Credential Guard isolates them in a VBS secure enclave.",
                        Confidence = 0.45, Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0
                    });
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[HardwareSecurityGuard] CredentialGuard check error"); }
        }
    }

    // 
    // DNS Cross Validator - detects router-level DNS poisoning by comparing
    // system resolver results against a direct DNS query to Cloudflare (1.1.1.1)
    // 
    public sealed class DnsCrossValidator : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<DnsCrossValidator> _logger;

        private const string TestDomain = "cloudflare.com";
        private static readonly IPAddress DirectDnsServer = IPAddress.Parse("1.1.1.1");
        private const int DnsPort = 53;

        public DnsCrossValidator(DetectionEngine de, SentinelConfig config, ILogger<DnsCrossValidator> l)
        {
            _detectionEngine = de; _config = config; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[DnsCrossValidator] Started");

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(60000, ct);
                    await CrossValidateDns(ct);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[DnsCrossValidator] Error"); }
            }
        }

        private async Task CrossValidateDns(CancellationToken ct)
        {
            try
            {
                // Step 1: Resolve via system resolver
                IPAddress[] systemResults;
                try
                {
                    systemResults = await DnsNet48.GetHostAddressesAsync(TestDomain, ct);
                }
                catch { return; } // No network - skip

                if (systemResults.Length == 0) return;

                // Step 2: Resolve via direct UDP query to 1.1.1.1
                var directResults = await DirectDnsQueryAsync(TestDomain, ct);
                if (directResults.Count == 0) return; // Couldn't reach 1.1.1.1

                // Step 3: Compare subnets (/16 for IPv4)
                var systemSubnets = systemResults
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => GetSubnet16(a))
                    .ToHashSet();

                var directSubnets = directResults
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => GetSubnet16(a))
                    .ToHashSet();

                if (systemSubnets.Count == 0 || directSubnets.Count == 0) return;

                // If there's ANY overlap in /16 subnets, it's legitimate CDN rotation
                if (systemSubnets.Overlaps(directSubnets)) return;

                // No subnet overlap - possible DNS poisoning at the router level
                await _detectionEngine.EmitAsync(new DetectionEvent
                {
                    RuleName = "DNS Poisoning: Router-Level DNS Manipulation Detected",
                    Evidence = $"Domain '{TestDomain}' - System resolver: [{string.Join(", ", systemResults.Select(a => a.ToString()))}] " +
                               $"(subnets: {string.Join(",", systemSubnets)}), " +
                               $"Direct 1.1.1.1: [{string.Join(", ", directResults.Select(a => a.ToString()))}] " +
                               $"(subnets: {string.Join(",", directSubnets)})",
                    Reasoning = "The system DNS resolver returned IPs in completely different /16 subnets than a direct " +
                                "query to Cloudflare's 1.1.1.1. This indicates the router or local network is poisoning DNS " +
                                "responses, redirecting traffic to attacker-controlled infrastructure. This bypasses hosts-file " +
                                "protections and certificate pinning may be the only remaining defense.",
                    Confidence = 0.92, Tier = DetectionTier.Tier1Behavioral,
                    AuthorizedResponse = ResponseAction.NetworkIsolate,
                    ProcessName = "SYSTEM", ProcessId = 0,
                    Metadata = new Dictionary<string, string>
                    {
                        ["Domain"] = TestDomain,
                        ["SystemIPs"] = string.Join(";", systemResults.Select(a => a.ToString())),
                        ["DirectIPs"] = string.Join(";", directResults.Select(a => a.ToString())),
                        ["TargetIP"] = systemResults.FirstOrDefault()?.ToString() ?? "",
                        // Root observation = router-level resolver divergence for this probe
                        // domain; independent of interface DNS config and ARP/route facts.
                        [BehavioralCorrelationEngine.ObservationKeyMeta] = $"dns-router:{TestDomain}"
                    }
                });
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[DnsCrossValidator] CrossValidate error"); }
        }

        /// <summary>
        /// Builds a minimal DNS A-record query packet and sends it directly to 1.1.1.1
        /// via UDP, bypassing the system resolver entirely.
        /// </summary>
        private static async Task<List<IPAddress>> DirectDnsQueryAsync(string domain, CancellationToken ct)
        {
            var results = new List<IPAddress>();
            try
            {
                // Build DNS query packet
                var packet = BuildDnsQuery(domain);

                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = 3000;
                var endpoint = new IPEndPoint(DirectDnsServer, DnsPort);

                await udp.SendAsync(packet, packet.Length, endpoint);

                // Wait for response with timeout
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeoutCts.CancelAfter(3000);

                var receiveTask = udp.ReceiveAsync();
                var result = await receiveTask;
                var response = result.Buffer;

                // Parse response - extract A records
                results = ParseDnsResponse(response);
            }
            catch { }
            return results;
        }

        /// <summary>
        /// Builds a minimal DNS query packet for an A record.
        /// Format: Header (12 bytes) + Question section (variable).
        /// </summary>
        private static byte[] BuildDnsQuery(string domain)
        {
            var ms = new System.IO.MemoryStream();
            var writer = new System.IO.BinaryWriter(ms);

            // Header: ID=0x1234, Flags=0x0100 (standard query, recursion desired)
            writer.Write((byte)0x12); writer.Write((byte)0x34); // Transaction ID
            writer.Write((byte)0x01); writer.Write((byte)0x00); // Flags: RD=1
            writer.Write((byte)0x00); writer.Write((byte)0x01); // Questions: 1
            writer.Write((byte)0x00); writer.Write((byte)0x00); // Answers: 0
            writer.Write((byte)0x00); writer.Write((byte)0x00); // Authority: 0
            writer.Write((byte)0x00); writer.Write((byte)0x00); // Additional: 0

            // Question section: domain name in DNS wire format
            foreach (var label in domain.Split('.'))
            {
                writer.Write((byte)label.Length);
                foreach (var ch in label)
                    writer.Write((byte)ch);
            }
            writer.Write((byte)0x00); // Null terminator

            // Type: A (1), Class: IN (1)
            writer.Write((byte)0x00); writer.Write((byte)0x01); // Type A
            writer.Write((byte)0x00); writer.Write((byte)0x01); // Class IN

            return ms.ToArray();
        }

        /// <summary>
        /// Parses a DNS response packet and extracts A record IP addresses.
        /// </summary>
        private static List<IPAddress> ParseDnsResponse(byte[] response)
        {
            var results = new List<IPAddress>();
            if (response.Length < 12) return results;

            // Answer count is at bytes 6-7
            int answerCount = (response[6] << 8) | response[7];
            if (answerCount == 0) return results;

            // Skip header (12 bytes) and question section
            int offset = 12;

            // Skip question section (one question)
            while (offset < response.Length && response[offset] != 0)
            {
                if ((response[offset] & 0xC0) == 0xC0)
                { offset += 2; break; } // Pointer
                offset += response[offset] + 1;
            }
            if (offset < response.Length && response[offset] == 0) offset++; // Null terminator
            offset += 4; // Skip QTYPE (2) + QCLASS (2)

            // Parse answer records
            for (int i = 0; i < answerCount && offset < response.Length - 10; i++)
            {
                // Skip name (may be pointer)
                if ((response[offset] & 0xC0) == 0xC0)
                    offset += 2;
                else
                {
                    while (offset < response.Length && response[offset] != 0)
                        offset += response[offset] + 1;
                    offset++; // Null terminator
                }

                if (offset + 10 > response.Length) break;

                int rtype = (response[offset] << 8) | response[offset + 1];
                offset += 2; // Type
                offset += 2; // Class
                offset += 4; // TTL
                int rdlength = (response[offset] << 8) | response[offset + 1];
                offset += 2; // RDLENGTH

                if (rtype == 1 && rdlength == 4 && offset + 4 <= response.Length)
                {
                    // A record: 4 bytes IPv4
                    results.Add(new IPAddress(new byte[]
                    {
                        response[offset], response[offset + 1],
                        response[offset + 2], response[offset + 3]
                    }));
                }
                offset += rdlength;
            }

            return results;
        }

        private static string GetSubnet16(IPAddress addr)
        {
            var bytes = addr.GetAddressBytes();
            return bytes.Length >= 2 ? $"{bytes[0]}.{bytes[1]}" : addr.ToString();
        }
    }

    // 
    // USB HID Whitelist - detects and disables unauthorized HID devices (BadUSB defense)
    // Baselines connected HID devices at startup, alerts and disables new unknown devices
    // 
    public sealed class UsbHidWhitelist : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<UsbHidWhitelist> _logger;

        private readonly HashSet<string> _baselineDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _alertedDevices = new(StringComparer.OrdinalIgnoreCase);

        // Built-in HID receivers - extended at runtime from Sentinel:TrustedUsbDevices
        private static readonly HashSet<string> BuiltInTrustedDevices = new(StringComparer.OrdinalIgnoreCase)
        {
            "VID_046D&PID_C52B", // Logitech Unifying Receiver
            "VID_046D&PID_C539", // Logitech Lightspeed Receiver
            "VID_046D&PID_C53F", // Logitech USB Receiver
            "VID_046D&PID_C548", // Logitech Bolt Receiver
        };

        private readonly HashSet<string> _trustedDevices;

        public UsbHidWhitelist(DetectionEngine de, SentinelConfig config, ILogger<UsbHidWhitelist> l)
        {
            _detectionEngine = de; _config = config; _logger = l;
            _trustedDevices = new HashSet<string>(BuiltInTrustedDevices, StringComparer.OrdinalIgnoreCase);
            // Merge operator allowlist (VID:PID or VID_xxxx&PID_yyyy)
            foreach (var entry in config.TrustedUsbDevices ?? Array.Empty<string>())
            {
                var n = UsbDeviceFingerprinter.NormalizeVidPid(entry);
                if (n == null) continue;
                var parts = n.Split(':');
                if (parts.Length == 2)
                    _trustedDevices.Add($"VID_{parts[0]}&PID_{parts[1]}");
            }
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UsbHidWhitelist] Started");

            // Baseline all currently connected HID devices
            var current = EnumerateHidDevices();
            foreach (var dev in current)
                _baselineDevices.Add(dev);
            _logger.LogInformation("[UsbHidWhitelist] Baseline: {Count} HID devices", _baselineDevices.Count);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(15000, ct);

                    var nowDevices = EnumerateHidDevices();
                    foreach (var dev in nowDevices)
                    {
                        if (_baselineDevices.Contains(dev)) continue;
                        if (_alertedDevices.Contains(dev)) continue;

                        // Extract VID_XXXX&PID_XXXX
                        var vidPid = ExtractVidPid(dev);
                        if (vidPid != null && _trustedDevices.Contains(vidPid))
                        {
                            _baselineDevices.Add(dev);
                            continue;
                        }

                        _alertedDevices.Add(dev);
                        _logger.LogWarning("[UsbHidWhitelist] New unauthorized HID: {Dev}", dev);

                        bool lockdown = ProductPosture.AllowsProactiveHostLockdown(_config);
                        if (lockdown)
                            DisableHidDevice(dev);

                        await _detectionEngine.EmitAsync(new DetectionEvent
                        {
                            RuleName = "BadUSB: Unauthorized HID Device Connected",
                            Evidence = lockdown
                                ? $"New HID device '{dev}' (VID:PID={vidPid ?? "unknown"}) not in whitelist or baseline. Attempted registry-level disable."
                                : $"New HID device '{dev}' (VID:PID={vidPid ?? "unknown"}) not in whitelist or baseline. Logged only (work-first: HID auto-disable requires Hardened Mode).",
                            Reasoning = "A new Human Interface Device appeared that was not present at startup and is not " +
                                        "in the trusted device whitelist. This may be a BadUSB/Rubber Ducky attack that " +
                                        "emulates a keyboard. Default work-first mode logs only so Xbox controllers, " +
                                        "wheels, and tablets keep working. Hardened Mode disables the device.",
                            Confidence = 0.88, Tier = DetectionTier.Tier1Behavioral,
                            AuthorizedResponse = ResponseAction.LogOnly,
                            ProcessName = "SYSTEM", ProcessId = 0,
                            SignalType = SignalType.PhantomKeystroke,
                            Metadata = new Dictionary<string, string>
                            {
                                ["DeviceId"] = dev,
                                ["VidPid"] = vidPid ?? "unknown",
                                ["Action"] = lockdown ? "RegistryDisable" : "LogOnly"
                            }
                        });
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UsbHidWhitelist] Error"); }
            }
        }

        private static List<string> EnumerateHidDevices()
        {
            var devices = new List<string>();
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\HID");
                if (key == null) return devices;

                foreach (var subKeyName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var deviceKey = key.OpenSubKey(subKeyName);
                        if (deviceKey == null) continue;
                        foreach (var instanceName in deviceKey.GetSubKeyNames())
                        {
                            devices.Add($"{subKeyName}\\{instanceName}");
                        }
                    }
                    catch { }
                }
            }
            catch { }
            return devices;
        }

        private static string? ExtractVidPid(string deviceId)
        {
            // Device IDs look like: VID_046D&PID_C52B\7&12345678&0&0000
            var upper = deviceId.ToUpperInvariant();
            var vidIdx = upper.IndexOf("VID_");
            var pidIdx = upper.IndexOf("PID_");
            if (vidIdx < 0 || pidIdx < 0) return null;

            try
            {
                var vid = upper.Substring(vidIdx, 8); // VID_XXXX
                var pid = upper.Substring(pidIdx, 8); // PID_XXXX
                return $"{vid}&{pid}";
            }
            catch { return null; }
        }

        private void DisableHidDevice(string deviceId)
        {
            try
            {
                var regPath = $@"SYSTEM\CurrentControlSet\Enum\HID\{deviceId}";
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true);
                if (key == null) return;

                // Set ConfigFlags to 1 (CONFIGFLAG_DISABLED) to disable the device
                key.SetValue("ConfigFlags", 1, RegistryValueKind.DWord);
                _logger.LogWarning("[UsbHidWhitelist] Disabled device via ConfigFlags: {Dev}", deviceId);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[UsbHidWhitelist] Failed to disable device {Dev}", deviceId);
            }
        }
    }

    // 
    // Traffic Volume Baseline - detects anomalous upload spikes from NIC-level implants
    // Monitors raw network interface BytesSent to catch exfiltration invisible to process monitoring
    // 
    public sealed class TrafficVolumeBaseline : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<TrafficVolumeBaseline> _logger;

        private readonly List<long> _baselineSamples = new();
        private long _lastBytesSent;
        private bool _baselineComplete;
        private double _baselineAverage;

        private const int BaselinePeriodSamples = 10; // 10 samples x 30s = 5 minutes
        private const double SpikeMultiplier = 3.0;

        public TrafficVolumeBaseline(DetectionEngine de, SentinelConfig config, ILogger<TrafficVolumeBaseline> l)
        {
            _detectionEngine = de; _config = config; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[TrafficVolumeBaseline] Started");

            // Initialize last bytes sent
            _lastBytesSent = GetTotalBytesSent();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    var currentBytesSent = GetTotalBytesSent();
                    var delta = currentBytesSent - _lastBytesSent;
                    _lastBytesSent = currentBytesSent;

                    if (delta < 0) delta = 0; // Counter reset

                    if (!_baselineComplete)
                    {
                        _baselineSamples.Add(delta);
                        if (_baselineSamples.Count >= BaselinePeriodSamples)
                        {
                            _baselineAverage = _baselineSamples.Average();
                            _baselineComplete = true;
                            _logger.LogInformation(
                                "[TrafficVolumeBaseline] Baseline complete: avg {Avg:F0} bytes/30s over {N} samples",
                                _baselineAverage, _baselineSamples.Count);
                        }
                        continue;
                    }

                    // After baseline: check for spikes
                    if (_baselineAverage > 0 && delta > _baselineAverage * SpikeMultiplier)
                    {
                        // v1.9.9: Torrent seeding / P2P / downloaders explain most home-user spikes.
                        // Observe only - never Exfil terminal, never Tier1.
                        if (BulkTransferNoise.IsAnyBulkTransferProcessRunning(out var bulkClient))
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Traffic Anomaly: Bulk Transfer Upload (Observe)",
                                Evidence =
                                    $"Upload bytes in last 30s: {delta:N0} while bulk-transfer client '{bulkClient}' is running " +
                                    $"(baseline avg: {_baselineAverage:N0}).",
                                Reasoning =
                                    "Upload volume spike coincides with a known torrent/P2P/downloader. " +
                                    "Seeding and bulk transfers are normal user activity - observe only.",
                                Confidence = 0.40,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = bulkClient ?? "SYSTEM",
                                ProcessId = 0,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["BulkTransfer"] = "true",
                                    ["BulkTransferClient"] = bulkClient ?? "",
                                    ["ObserveOnly"] = "true",
                                    ["WeakObserveSeed"] = "true",
                                    ["ActualBytes"] = delta.ToString(),
                                    ["BaselineAvg"] = _baselineAverage.ToString("F0"),
                                    ["Ratio"] = (delta / _baselineAverage).ToString("F1")
                                }
                            });
                        }
                        else
                        {
                            await _detectionEngine.EmitAsync(new DetectionEvent
                            {
                                RuleName = "Traffic Anomaly: Upload Volume Spike Detected",
                                Evidence = $"Upload bytes in last 30s: {delta:N0} (baseline avg: {_baselineAverage:N0}, " +
                                           $"threshold: {_baselineAverage * SpikeMultiplier:N0}, ratio: {delta / _baselineAverage:F1}x)",
                                Reasoning =
                                    "Network upload volume exceeded 3x the baseline average (no known bulk-transfer client detected). " +
                                    "Observe-only host-wide signal - not process-attributed. " +
                                    "May indicate heavy upload or rare process-invisible stack abuse; does not alone authorize response.",
                                Confidence = 0.55,
                                Tier = DetectionTier.Tier2Indicator,
                                AuthorizedResponse = ResponseAction.LogOnly,
                                ProcessName = "SYSTEM",
                                ProcessId = 0,
                                SignalType = SignalType.Generic,
                                Metadata = new Dictionary<string, string>
                                {
                                    ["ActualBytes"] = delta.ToString(),
                                    ["BaselineAvg"] = _baselineAverage.ToString("F0"),
                                    ["Ratio"] = (delta / _baselineAverage).ToString("F1"),
                                    ["ObserveOnly"] = "true",
                                    ["WeakObserveSeed"] = "true"
                                }
                            });
                        }
                    }

                    // Slowly adapt baseline (exponential moving average)
                    _baselineAverage = _baselineAverage * 0.9 + delta * 0.1;
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[TrafficVolumeBaseline] Error"); }
            }
        }

        private static long GetTotalBytesSent()
        {
            long total = 0;
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    var stats = ni.GetIPStatistics();
                    total += stats.BytesSent;
                }
            }
            catch { }
            return total;
        }
    }

    // 
    // Outbound Connection Whitelist - enforces or monitors outbound connections
    // against a whitelist of allowed subnets. Nuclear option for implant exfiltration.
    // 
    public sealed class OutboundConnectionWhitelist : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<OutboundConnectionWhitelist> _logger;

        private readonly ConcurrentDictionary<string, DateTime> _alertedIps = new();

        // Hardcoded defaults - in production, read from Sentinel.AllowedOutboundSubnets
        private static readonly (uint Network, uint Mask)[] AllowedSubnets = new[]
        {
            ParseCidr("142.250.0.0/16"),   // Google
            ParseCidr("162.159.0.0/16"),   // Cloudflare
            ParseCidr("54.84.0.0/16"),     // AWS us-east-1
            ParseCidr("35.0.0.0/8"),       // Google Cloud
            ParseCidr("140.82.0.0/16"),    // GitHub
            ParseCidr("185.199.0.0/16"),   // GitHub Pages
            ParseCidr("20.0.0.0/8"),       // Microsoft Azure
            ParseCidr("52.0.0.0/8"),       // AWS
            ParseCidr("104.0.0.0/8"),      // Cloudflare/Akamai
            ParseCidr("13.0.0.0/8"),       // Microsoft
            ParseCidr("192.168.0.0/16"),   // LAN
            ParseCidr("10.0.0.0/8"),       // LAN
            ParseCidr("172.16.0.0/12"),    // LAN
            ParseCidr("127.0.0.0/8"),      // Localhost
        };

        // Whether to actively enforce via Windows Firewall (nuclear option)
        private bool _enforcementMode;
        private bool _firewallRuleCreated;

        private const string FirewallRuleName = "Sentinel-OutboundWhitelist-Block";

        public OutboundConnectionWhitelist(DetectionEngine de, SentinelConfig config, ILogger<OutboundConnectionWhitelist> l)
        {
            _detectionEngine = de; _config = config; _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[OutboundConnectionWhitelist] Started");

            // Check enforcement mode from registry (Sentinel.OutboundWhitelistEnforced)
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Sentinel\Config");
                var val = key?.GetValue("OutboundWhitelistEnforced");
                _enforcementMode = val is int v && v == 1;
            }
            catch { _enforcementMode = false; }

            if (_enforcementMode)
            {
                _logger.LogWarning("[OutboundConnectionWhitelist] ENFORCEMENT MODE - creating firewall block rule");
                CreateFirewallBlockRule();
            }
            else
            {
                _logger.LogInformation("[OutboundConnectionWhitelist] Monitor-only mode - scanning netstat");
            }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(30000, ct);

                    if (!_enforcementMode)
                    {
                        await ScanOutboundConnections(ct);
                    }

                    // Prune old alerted IPs (older than 5 minutes)
                    var stale = _alertedIps.Where(kv => DateTime.UtcNow - kv.Value > TimeSpan.FromMinutes(5))
                        .Select(kv => kv.Key).ToList();
                    foreach (var ip in stale) _alertedIps.TryRemove(ip, out _);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[OutboundConnectionWhitelist] Error"); }
            }
        }

        private async Task ScanOutboundConnections(CancellationToken ct)
        {
            try
            {
                var psi = new ProcessStartInfo("netstat.exe", "-n -p TCP")
                {
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                using var proc = Process.Start(psi);
                if (proc == null) return;

                var output = await proc.StandardOutput.ReadToEndAsync();
                proc.WaitForExit(5000);

                foreach (var line in output.Split('\n'))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP")) continue;
                    if (!trimmed.Contains("ESTABLISHED")) continue;

                    // Parse: TCP    192.168.1.100:12345    142.250.80.46:443    ESTABLISHED
                    var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 4) continue;

                    var remoteEndpoint = parts[2];
                    var lastColon = remoteEndpoint.LastIndexOf(':');
                    if (lastColon <= 0) continue;

                    var remoteIpStr = remoteEndpoint[..lastColon];
                    if (!IPAddress.TryParse(remoteIpStr, out var remoteIp)) continue;
                    if (remoteIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) continue;

                    if (IsAllowed(remoteIp)) continue;
                    if (_alertedIps.ContainsKey(remoteIpStr)) continue;

                    _alertedIps[remoteIpStr] = DateTime.UtcNow;

                    await _detectionEngine.EmitAsync(new DetectionEvent
                    {
                        RuleName = "Outbound Whitelist: Connection to Non-Whitelisted IP",
                        Evidence = $"Established TCP connection to {remoteEndpoint} - IP not in allowed subnets",
                        Reasoning = "An outbound connection was established to an IP address not in the configured " +
                                    "whitelist of allowed subnets. This may indicate implant C2 communication, " +
                                    "data exfiltration, or unauthorized network activity.",
                        Confidence = 0.65, Tier = DetectionTier.Tier2Indicator,
                        AuthorizedResponse = ResponseAction.LogOnly,
                        ProcessName = "SYSTEM", ProcessId = 0,
                        Metadata = new Dictionary<string, string>
                        {
                            ["RemoteIP"] = remoteIpStr,
                            ["TargetIP"] = remoteIpStr
                        }
                    });
                }
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[OutboundConnectionWhitelist] Scan error"); }
        }

        /// <summary>
        /// Creates a Windows Firewall outbound block rule that blocks ALL traffic
        /// except whitelisted subnets + localhost + LAN. The nuclear option.
        /// </summary>
        private void CreateFirewallBlockRule()
        {
            if (_firewallRuleCreated) return;
            try
            {
                // Build allowed remote addresses string for the allow rule
                var allowedAddresses = string.Join(",",
                    AllowedSubnets.Select(s =>
                    {
                        var network = new IPAddress(BitConverter.GetBytes(s.Network)).ToString();
                        int prefix = CountBits(s.Mask);
                        return $"{network}/{prefix}";
                    }));

                // Strategy: Create a BLOCK ALL outbound rule, then an ALLOW rule for whitelisted
                // Windows Firewall processes rules in order: Allow rules take precedence over Block

                // First: Allow rule for whitelisted subnets
                var allowPsi = new ProcessStartInfo("netsh.exe",
                    $"advfirewall firewall add rule name=\"Sentinel-OutboundWhitelist-Allow\" " +
                    $"dir=out action=allow remoteip=\"{allowedAddresses}\"")
                {
                    CreateNoWindow = true, UseShellExecute = false
                };
                using (var p = Process.Start(allowPsi))
                    p?.WaitForExit(5000);

                // Then: Block everything else
                var blockPsi = new ProcessStartInfo("netsh.exe",
                    $"advfirewall firewall add rule name=\"{FirewallRuleName}\" " +
                    "dir=out action=block remoteip=any")
                {
                    CreateNoWindow = true, UseShellExecute = false
                };
                using (var p = Process.Start(blockPsi))
                    p?.WaitForExit(5000);

                _firewallRuleCreated = true;
                _logger.LogWarning("[OutboundConnectionWhitelist] Firewall enforcement rules created");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[OutboundConnectionWhitelist] Failed to create firewall rules");
            }
        }

        private static bool IsAllowed(IPAddress ip)
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length != 4) return true; // Only check IPv4

            uint ipInt = (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);

            foreach (var (network, mask) in AllowedSubnets)
            {
                if ((ipInt & mask) == network)
                    return true;
            }
            return false;
        }

        private static (uint Network, uint Mask) ParseCidr(string cidr)
        {
            var parts = cidr.Split('/');
            var ip = IPAddress.Parse(parts[0]);
            var prefixLen = int.Parse(parts[1]);
            var ipBytes = ip.GetAddressBytes();
            uint ipInt = (uint)(ipBytes[0] << 24 | ipBytes[1] << 16 | ipBytes[2] << 8 | ipBytes[3]);
            uint mask = prefixLen == 0 ? 0 : 0xFFFFFFFF << (32 - prefixLen);
            return (ipInt & mask, mask);
        }

        private static int CountBits(uint mask)
        {
            int count = 0;
            while (mask != 0)
            {
                count += (int)(mask & 1);
                mask >>= 1;
            }
            return count;
        }
    }
}
