using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Detects signs of physical tampering by correlating idle periods with
    /// new USB/Bluetooth devices, new logon sessions, and input activity spikes.
    /// v1.4.5: New monitor.
    /// </summary>
    public sealed class PhysicalAccessMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PhysicalAccessMonitor> _logger;

        private readonly HashSet<string> _baselineUsbDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _baselineBluetoothDevices = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<int> _baselineSessionIds = new();
        private bool _wasIdle;
        private DateTime _idleStartTime = DateTime.MinValue;

        private const int AlertCooldownSeconds = 60;
        private readonly Dictionary<string, DateTime> _categoryLastAlert = new();

        // If no input for 2 minutes, user is "away"
        private const uint IdleThresholdMs = 120_000;

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("kernel32.dll")]
        private static extern uint GetTickCount();

        public PhysicalAccessMonitor(DetectionEngine de, ILogger<PhysicalAccessMonitor> l)
        {
            _detectionEngine = de;
            _logger = l;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[PhysicalAccessMonitor] Started");

            SnapshotUsbDevices(_baselineUsbDevices);
            SnapshotBluetoothDevices(_baselineBluetoothDevices);
            SnapshotSessionIds(_baselineSessionIds);

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(10000, ct);

                    uint currentTick = GetCurrentInputTick();
                    uint elapsed = GetTickCount() - currentTick;
                    bool isIdle = elapsed > IdleThresholdMs;

                    if (isIdle && !_wasIdle)
                    {
                        _wasIdle = true;
                        _idleStartTime = DateTime.UtcNow;
                    }
                    else if (!isIdle && _wasIdle)
                    {
                        _wasIdle = false;
                        var idleDuration = DateTime.UtcNow - _idleStartTime;
                        await CheckPostIdleAnomalies(idleDuration, ct);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[PhysicalAccessMonitor] Error"); }
            }
        }

        private async Task CheckPostIdleAnomalies(TimeSpan idleDuration, CancellationToken ct)
        {
            var anomalies = new List<string>();

            // Check for new USB devices
            var currentUsb = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            SnapshotUsbDevices(currentUsb);
            var newUsb = currentUsb.Except(_baselineUsbDevices).ToList();
            if (newUsb.Count > 0)
            {
                anomalies.Add($"New USB devices: {string.Join(", ", newUsb.Take(3))}");
                foreach (var dev in newUsb) _baselineUsbDevices.Add(dev);
            }

            // Check for new Bluetooth devices
            var currentBt = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            SnapshotBluetoothDevices(currentBt);
            var newBt = currentBt.Except(_baselineBluetoothDevices).ToList();
            if (newBt.Count > 0)
            {
                anomalies.Add($"New Bluetooth devices: {string.Join(", ", newBt.Take(3))}");
                foreach (var dev in newBt) _baselineBluetoothDevices.Add(dev);
            }

            // Check for new logon sessions
            var currentSessions = new HashSet<int>();
            SnapshotSessionIds(currentSessions);
            var newSessions = currentSessions.Except(_baselineSessionIds).ToList();
            if (newSessions.Count > 0)
            {
                anomalies.Add($"New session IDs: {string.Join(", ", newSessions)}");
                foreach (var s in newSessions) _baselineSessionIds.Add(s);
            }

            if (anomalies.Count == 0) return;
            if (!CanAlert("PhysicalAccess")) return;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Physical Access: Post-Idle Anomalies Detected",
                Evidence = $"After {idleDuration.TotalMinutes:F1}min idle: {string.Join("; ", anomalies)}",
                Reasoning = "Hardware or session changes occurred while the user was idle, which may indicate " +
                            "physical access by an unauthorized person. New USB devices during idle could be " +
                            "a BadUSB attack, new sessions could indicate credential theft or shoulder-surfing.",
                Confidence = anomalies.Count >= 2 ? 0.75 : 0.55,
                Tier = anomalies.Count >= 2 ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0
            });
        }

        private bool CanAlert(string category)
        {
            if (_categoryLastAlert.TryGetValue(category, out var last))
            {
                if ((DateTime.UtcNow - last).TotalSeconds < AlertCooldownSeconds)
                    return false;
            }
            _categoryLastAlert[category] = DateTime.UtcNow;
            return true;
        }

        private static uint GetCurrentInputTick()
        {
            var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
            return GetLastInputInfo(ref info) ? info.dwTime : GetTickCount();
        }

        private static void SnapshotUsbDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB");
                if (key == null) return;
                foreach (var vidPid in key.GetSubKeyNames())
                {
                    try
                    {
                        using var vidKey = key.OpenSubKey(vidPid);
                        if (vidKey == null) continue;
                        foreach (var serial in vidKey.GetSubKeyNames())
                        {
                            target.Add($"{vidPid}\\{serial}");
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        private static void SnapshotBluetoothDevices(HashSet<string> target)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices");
                if (key == null) return;
                foreach (var sub in key.GetSubKeyNames())
                    target.Add(sub);
            }
            catch { }
        }

        private static void SnapshotSessionIds(HashSet<int> target)
        {
            try
            {
                foreach (var proc in Process.GetProcessesByName("explorer"))
                {
                    try { target.Add(proc.SessionId); }
                    catch { }
                    finally { proc.Dispose(); }
                }
            }
            catch { }
        }
    }
}
