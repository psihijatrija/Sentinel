using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    public class UsbDevice
    {
        public string DeviceId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Vid { get; set; } = string.Empty;
        public string Pid { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public bool IsHid { get; set; }
        public bool IsMassStorage { get; set; }
        public bool IsComposite { get; set; }
        public bool IsFailedEnumeration { get; set; }
    }

    public class UsbDeviceFingerprinter : IDisposable
    {
        private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _trustedVidPid;
        private readonly System.Threading.Timer _timer;
        private readonly DetectionEngine _detectionEngine;
        private readonly SentinelConfig _config;
        private readonly ILogger<UsbDeviceFingerprinter>? _logger;

        // Known good keyboard VIDs (Logitech, Microsoft, Razer, Corsair, Apple, Keychron, etc.)
        private static readonly HashSet<string> AllowedKeyboardVids = new(StringComparer.OrdinalIgnoreCase)
        {
            "046D", // Logitech
            "045E", // Microsoft
            "1532", // Razer
            "1B1C", // Corsair
            "05AC", // Apple
            "3434", // Keychron
            "0951", // Kingston/HyperX
            "04F2", // Chicony
            "0C45"  // SINO WEALTH
        };

        // Built-in trusted storage VID:PID (operator can extend via Sentinel:TrustedUsbDevices)
        private static readonly string[] DefaultTrustedUsb = new[]
        {
            "0951:1666", // Kingston DataTraveler 3.0 (common Ventoy stick)
        };

        public UsbDeviceFingerprinter(
            DetectionEngine detectionEngine,
            SentinelConfig? config = null,
            ILogger<UsbDeviceFingerprinter>? logger = null)
        {
            _detectionEngine = detectionEngine;
            _config = config ?? new SentinelConfig();
            _logger = logger;
            _trustedVidPid = BuildTrustedSet(_config.TrustedUsbDevices);

            // Baseline connected devices
            var devices = GetConnectedUsbDevices();
            foreach (var d in devices)
            {
                _baseline.Add(d.DeviceId);
            }

            // v1.6.9 / v1.7.2: Scan baseline for failed-enumeration zombies and fully remove them.
            // Disable alone leaves ConfigFlags=1 nodes present -> sticky Windows tray icon.
            if (_config.AutoDisableFailedUsbEnumeration)
                SweepAndRemoveFailedEnumerationDevices(devices, isBaseline: true);

            _logger?.LogInformation(
                "[UsbDeviceFingerprinter] Baseline {Count} USB devices; {Trusted} trusted VID:PID; AutoDisableFailedEnum={Auto}",
                _baseline.Count, _trustedVidPid.Count, _config.AutoDisableFailedUsbEnumeration);

            // Poll every 30s
            _timer = new System.Threading.Timer(PollUsbDevices, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        private static HashSet<string> BuildTrustedSet(string[]? configured)
        {
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in DefaultTrustedUsb.Concat(configured ?? Array.Empty<string>()))
            {
                var normalized = NormalizeVidPid(entry);
                if (normalized != null)
                    set.Add(normalized);
            }
            return set;
        }

        /// <summary>Accepts "0951:1666", "VID_0951&PID_1666", "0951-1666".</summary>
        internal static string? NormalizeVidPid(string? raw)
        {
            if (string.IsNullOrWhiteSpace(raw)) return null;
            var s = raw!.Trim().ToUpperInvariant()
                .Replace("VID_", "")
                .Replace("PID_", "")
                .Replace("&", ":")
                .Replace("-", ":")
                .Replace(" ", "");
            var parts = s.Split(new[] { ':' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2) return null;
            if (parts[0].Length != 4 || parts[1].Length != 4) return null;
            return $"{parts[0]}:{parts[1]}";
        }

        private void PollUsbDevices(object? state)
        {
            try
            {
                var currentDevices = GetConnectedUsbDevices();
                foreach (var dev in currentDevices)
                {
                    if (!_baseline.Contains(dev.DeviceId))
                    {
                        ProcessNewDevice(dev);
                        // Only baseline if still present - successful failed-enum removal
                        // clears the node; re-adding would hide future re-plugs incorrectly
                        // and would undo ProcessNewDevice's _baseline.Remove on success.
                        if (DeviceNodePresent(dev.DeviceId))
                            _baseline.Add(dev.DeviceId);
                    }
                }

                // v1.7.2: Re-sweep baselined failed-enum zombies. Earlier eject can return
                // CR_SUCCESS while the node stays Disabled (ConfigFlags=1), leaving the tray icon.
                if (_config.AutoDisableFailedUsbEnumeration)
                    SweepAndRemoveFailedEnumerationDevices(currentDevices, isBaseline: false);
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Poll error");
            }
        }

        /// <summary>
        /// v1.7.2: Disable + fully remove every failed-enumeration device still present.
        /// Removes instance IDs from baseline when the node is gone so a re-plug is re-detected.
        /// </summary>
        private void SweepAndRemoveFailedEnumerationDevices(IEnumerable<UsbDevice> devices, bool isBaseline)
        {
            foreach (var d in devices)
            {
                if (!IsFailedEnumerationDevice(d)) continue;

                _logger?.LogWarning(
                    "[UsbDeviceFingerprinter] {Phase} failed-enumeration device - removing: {Id} ({Name})",
                    isBaseline ? "Baseline" : "Periodic",
                    d.DeviceId, d.Name);

                DisableUsbDevice(d.DeviceId);
                bool removed = EjectUsbDevice(d.DeviceId);
                if (removed)
                    _baseline.Remove(d.DeviceId);
            }
        }

        /// <summary>
        /// v1.6.9 / v1.7.2: True failed-enumeration only - VID_0000 or real Windows failure
        /// descriptions. Never treats blank friendly names as failed (that caused disable FPs).
        /// </summary>
        internal static bool IsFailedEnumerationDevice(UsbDevice dev)
        {
            if (dev.IsFailedEnumeration) return true;
            return IsFailedEnumerationSignals(dev.Vid, dev.Name);
        }

        /// <summary>
        /// Pure classification used by enumeration and tests.
        /// Windows labels real failures as e.g. "Unknown USB Device (Device Descriptor Request Failed)".
        /// A bare blank name is NOT a failure.
        /// </summary>
        internal static bool IsFailedEnumerationSignals(string? vid, string? name)
        {
            if (vid != null && vid.Equals("0000"))
                return true;

            if (string.IsNullOrWhiteSpace(name))
                return false;

            // Exact Windows USB failure substrings (usb.inf device_descriptor_failure etc.)
            if (name!.Contains("Device Descriptor Request Failed"))
                return true;
            if (name.Contains("Device Descriptor Failure"))
                return true;
            if (name.Contains("Port Reset Failed"))
                return true;
            if (name.Contains("Set Address Failed"))
                return true;

            // Windows always appends a parenthetical reason for unknown/failed USB devices.
            // Require the parenthesis so we never match an invented bare "Unknown USB Device".
            if (name.StartsWith("Unknown USB Device ("))
                return true;

            return false;
        }

        private void ProcessNewDevice(UsbDevice dev)
        {
            string ruleName = "USB: New Device Connected";
            string evidence = $"USB device '{dev.Name}' with VID {dev.Vid} PID {dev.Pid} connected.";
            double confidence = 0.40;
            DetectionTier tier = DetectionTier.Tier2Indicator;
            ResponseAction response = ResponseAction.LogOnly;
            bool disabled = false;
            var vidPid = $"{dev.Vid}:{dev.Pid}";

            // v1.6.3: Failed enumeration / VID_0000 - high interest, auto-disable
            if (IsFailedEnumerationDevice(dev))
            {
                ruleName = "USB: Failed Device Enumeration";
                evidence = $"USB device failed descriptor enumeration: '{dev.Name}' " +
                           $"(VID {dev.Vid} PID {dev.Pid}, InstanceId={dev.DeviceId}). " +
                           "Windows could not read the device identity - flaky port/cable, " +
                           "or hostile hardware that refuses to identify.";
                confidence = 0.82;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly;

                if (_config.AutoDisableFailedUsbEnumeration)
                {
                    disabled = DisableUsbDevice(dev.DeviceId);
                    evidence += disabled
                        ? " Device disabled via registry ConfigFlags."
                        : " Auto-disable attempted but registry write failed.";

                    // v1.6.4 / v1.7.2: Full PnP removal - verify node gone (not just eject CR_SUCCESS)
                    bool ejected = EjectUsbDevice(dev.DeviceId);
                    evidence += ejected
                        ? " Device removed from PnP tree."
                        : " PnP removal attempted but device node still present (tray icon may linger).";
                    if (ejected)
                        _baseline.Remove(dev.DeviceId);
                }
            }
            else if (_trustedVidPid.Contains(vidPid))
            {
                ruleName = "USB: Trusted Device Connected";
                evidence = $"Trusted USB device '{dev.Name}' (VID {dev.Vid} PID {dev.Pid}) connected - allowlisted.";
                confidence = 0.15;
                tier = DetectionTier.Tier2Indicator;
                response = ResponseAction.LogOnly;
            }
            else if (dev.IsHid && !AllowedKeyboardVids.Contains(dev.Vid))
            {
                ruleName = "BadUSB: Unknown HID Device";
                evidence = $"Unknown HID keyboard device '{dev.Name}' (VID {dev.Vid}) connected.";
                confidence = 0.80;
                tier = DetectionTier.Tier1Behavioral;
                response = ResponseAction.LogOnly;
                // Work-first: never disable/eject HID on a default install.
                // Xbox controllers, wheels, HOTAS, tablets, and 2.4 GHz receivers
                // appear as unknown HID after boot. Kiosk only.
                if (ProductPosture.AllowsProactiveHostLockdown(_config))
                {
                    disabled = DisableUsbDevice(dev.DeviceId);
                    if (disabled)
                        evidence += " Device disabled via registry ConfigFlags.";

                    bool ejected = EjectUsbDevice(dev.DeviceId);
                    if (ejected)
                    {
                        evidence += " Device removed from PnP tree.";
                        _baseline.Remove(dev.DeviceId);
                    }
                }
                else
                {
                    evidence += " Logged only (work-first: HID auto-disable requires Hardened Mode).";
                }
            }
            else if (dev.IsComposite)
            {
                ruleName = "USB: New Composite Device";
                evidence = $"New composite USB device '{dev.Name}' (VID {dev.Vid}) connected.";
                confidence = 0.75;
                tier = DetectionTier.Tier1Behavioral;
            }
            else if (dev.IsMassStorage)
            {
                ruleName = "USB: New Mass Storage Device";
                evidence = $"New mass storage USB device '{dev.Name}' (VID {dev.Vid} PID {dev.Pid}) connected.";
                confidence = 0.50;
                tier = DetectionTier.Tier2Indicator;
            }

            var detection = new DetectionEvent
            {
                RuleName = ruleName,
                ProcessName = "SentinelService.exe",
                ProcessId = System.Net48Environment.ProcessId,
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = response,
                Evidence = evidence,
                Reasoning = $"New unbaselined USB device detected at runtime. Action tier resolved to {tier}." +
                            (disabled ? " Auto-disabled." : "") +
                            (evidence.Contains("removed from PnP tree") ? " Removed." : ""),
                Metadata = new Dictionary<string, string>
                {
                    { "VID", dev.Vid },
                    { "PID", dev.Pid },
                    { "DeviceName", dev.Name ?? "" },
                    { "Serial", dev.SerialNumber ?? "" },
                    { "DeviceId", dev.DeviceId ?? "" },
                    { "FailedEnumeration", IsFailedEnumerationDevice(dev).ToString() },
                    { "Disabled", disabled.ToString() },
                    { "Ejected", evidence.Contains("removed from PnP tree").ToString() },
                    { "Trusted", _trustedVidPid.Contains(vidPid).ToString() }
                }
            };

            _ = _detectionEngine.EmitAsync(detection);
        }

        /// <summary>
        /// Disables a PnP device by setting ConfigFlags=CONFIGFLAG_DISABLED (1) under Enum.
        /// Same technique as UsbHidWhitelist - requires service to run as SYSTEM/admin.
        /// </summary>
        internal bool DisableUsbDevice(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                // Instance IDs look like: USB\VID_0000&PID_0002\5&230b5917&0&1
                var regPath = $@"SYSTEM\CurrentControlSet\Enum\{deviceInstanceId}";
                using var key = Registry.LocalMachine.OpenSubKey(regPath, writable: true);
                if (key == null)
                {
                    _logger?.LogDebug("[UsbDeviceFingerprinter] Enum key not found for disable: {Id}", deviceInstanceId);
                    return false;
                }

                key.SetValue("ConfigFlags", 1, RegistryValueKind.DWord);
                _logger?.LogWarning("[UsbDeviceFingerprinter] Disabled USB device via ConfigFlags: {Id}", deviceInstanceId);
                return true;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Failed to disable {Id}", deviceInstanceId);
                return false;
            }
        }

        /// <summary>
        /// v1.6.4 / v1.7.2: Fully removes a USB device from the PnP tree so the Windows
        /// "USB device not recognized" tray icon clears.
        ///
        /// Critical v1.7.2 change: each strategy is verified with <see cref="DeviceNodePresent"/>.
        /// CM_Request_Device_Eject can return CR_SUCCESS while leaving a ConfigFlags-disabled
        /// zombie node (the production sticky-icon case). Previous code treated CR_SUCCESS as
        /// done and skipped pnputil.
        ///
        /// Call AFTER DisableUsbDevice when auto-disabling hostile/failed devices.
        /// </summary>
        internal bool EjectUsbDevice(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;

            if (!DeviceNodePresent(deviceInstanceId))
            {
                _logger?.LogDebug("[UsbDeviceFingerprinter] Device already absent: {Id}", deviceInstanceId);
                return true;
            }

            // Strategy 1: CM_Request_Device_Eject on the device (+ HELD_FOR_EJECT handling)
            TryEjectViaCfgMgr(deviceInstanceId);
            Thread.Sleep(150);
            if (!DeviceNodePresent(deviceInstanceId))
            {
                _logger?.LogWarning("[UsbDeviceFingerprinter] Removed USB device via CM_Request_Device_Eject: {Id}", deviceInstanceId);
                return true;
            }

            // Strategy 2: Eject parent hub port (error-state child nodes often need this)
            TryEjectParentViaCfgMgr(deviceInstanceId);
            Thread.Sleep(150);
            if (!DeviceNodePresent(deviceInstanceId))
            {
                _logger?.LogWarning("[UsbDeviceFingerprinter] Removed USB device via parent hub eject: {Id}", deviceInstanceId);
                return true;
            }

            // Strategy 3: pnputil /remove-device - required for ConfigFlags=1 disabled zombies
            if (TryEjectViaPnputil(deviceInstanceId))
            {
                Thread.Sleep(200);
                if (!DeviceNodePresent(deviceInstanceId))
                {
                    _logger?.LogWarning("[UsbDeviceFingerprinter] Removed USB device via pnputil: {Id}", deviceInstanceId);
                    return true;
                }
            }

            // Strategy 4: CM_Disable_DevNode on the device (not parent hub) then pnputil again
            TryDisableDevNodeOnly(deviceInstanceId);
            if (TryEjectViaPnputil(deviceInstanceId))
            {
                Thread.Sleep(200);
                if (!DeviceNodePresent(deviceInstanceId))
                {
                    _logger?.LogWarning("[UsbDeviceFingerprinter] Removed USB device via disable+pnputil: {Id}", deviceInstanceId);
                    return true;
                }
            }

            // Strategy 5 (last resort): disable parent port only if still HELD_FOR_EJECT, then pnputil.
            // Avoids taking down healthy siblings on the hub unless the OS is stuck on eject.
            if (TryDisableParentIfHeldForEject(deviceInstanceId) && TryEjectViaPnputil(deviceInstanceId))
            {
                Thread.Sleep(200);
                if (!DeviceNodePresent(deviceInstanceId))
                {
                    _logger?.LogWarning("[UsbDeviceFingerprinter] Removed USB device after parent HELD_FOR_EJECT disable: {Id}", deviceInstanceId);
                    return true;
                }
            }

            _logger?.LogWarning("[UsbDeviceFingerprinter] All removal strategies failed - node still present: {Id}", deviceInstanceId);
            return false;
        }

        /// <summary>
        /// True if the device instance still exists as a live or phantom PnP node.
        /// </summary>
        internal bool DeviceNodePresent(string deviceInstanceId)
        {
            if (string.IsNullOrWhiteSpace(deviceInstanceId)) return false;
            try
            {
                int result = CM_Locate_DevNode(out _, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (result == CR_SUCCESS) return true;
                // Phantom: still in the enum tree after disable - tray icon can remain
                result = CM_Locate_DevNode(out _, deviceInstanceId, CM_LOCATE_DEVNODE_PHANTOM);
                return result == CR_SUCCESS;
            }
            catch
            {
                return false;
            }
        }

        private bool TryEjectViaCfgMgr(string deviceInstanceId)
        {
            try
            {
                int result = CM_Locate_DevNode(out int devInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (result != CR_SUCCESS)
                {
                    // Device may already be in phantom state after disable - try phantom flag
                    result = CM_Locate_DevNode(out devInst, deviceInstanceId, CM_LOCATE_DEVNODE_PHANTOM);
                    if (result != CR_SUCCESS)
                    {
                        _logger?.LogDebug("[UsbDeviceFingerprinter] CM_Locate_DevNode failed ({Err}) for: {Id}", result, deviceInstanceId);
                        return false;
                    }
                }

                result = CM_Request_Device_Eject(devInst, out int vetoType, IntPtr.Zero, 0, 0);
                if (result == CR_SUCCESS)
                {
                    // v1.7.1 / v1.7.2: If stuck in HELD_FOR_EJECT, disable the device node itself
                    // (not the whole parent hub - that can break healthy siblings). Parent disable
                    // is deferred to the last-resort path in EjectUsbDevice.
                    Thread.Sleep(200);
                    int relocResult = CM_Locate_DevNode(out int checkInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                    if (relocResult == CR_SUCCESS)
                    {
                        CM_Get_DevNode_Status(out _, out int problemNumber, checkInst, 0);
                        if (problemNumber == CM_PROB_HELD_FOR_EJECT)
                        {
                            _logger?.LogWarning(
                                "[UsbDeviceFingerprinter] Device stuck in HELD_FOR_EJECT - disabling device node: {Id}",
                                deviceInstanceId);
                            CM_Disable_DevNode(checkInst, 0);
                        }
                    }
                    // CR_SUCCESS does NOT mean the node is gone - caller must verify.
                    return true;
                }

                _logger?.LogDebug("[UsbDeviceFingerprinter] CM_Request_Device_Eject failed ({Err}, veto={Veto}) for: {Id}",
                    result, vetoType, deviceInstanceId);
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] CfgMgr eject exception for: {Id}", deviceInstanceId);
                return false;
            }
        }

        private bool TryDisableDevNodeOnly(string deviceInstanceId)
        {
            try
            {
                int result = CM_Locate_DevNode(out int devInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (result != CR_SUCCESS)
                    result = CM_Locate_DevNode(out devInst, deviceInstanceId, CM_LOCATE_DEVNODE_PHANTOM);
                if (result != CR_SUCCESS) return false;

                result = CM_Disable_DevNode(devInst, 0);
                return result == CR_SUCCESS;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] CM_Disable_DevNode exception for: {Id}", deviceInstanceId);
                return false;
            }
        }

        private bool TryDisableParentIfHeldForEject(string deviceInstanceId)
        {
            try
            {
                int result = CM_Locate_DevNode(out int devInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (result != CR_SUCCESS)
                    result = CM_Locate_DevNode(out devInst, deviceInstanceId, CM_LOCATE_DEVNODE_PHANTOM);
                if (result != CR_SUCCESS) return false;

                CM_Get_DevNode_Status(out _, out int problemNumber, devInst, 0);
                if (problemNumber != CM_PROB_HELD_FOR_EJECT)
                    return false;

                result = CM_Get_Parent(out int parentInst, devInst, 0);
                if (result != CR_SUCCESS) return false;

                _logger?.LogWarning(
                    "[UsbDeviceFingerprinter] Last resort: disabling parent hub port for HELD_FOR_EJECT: {Id}",
                    deviceInstanceId);
                return CM_Disable_DevNode(parentInst, 0) == CR_SUCCESS;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Parent HELD_FOR_EJECT disable exception for: {Id}", deviceInstanceId);
                return false;
            }
        }

        private bool TryEjectParentViaCfgMgr(string deviceInstanceId)
        {
            try
            {
                int result = CM_Locate_DevNode(out int devInst, deviceInstanceId, CM_LOCATE_DEVNODE_NORMAL);
                if (result != CR_SUCCESS)
                    result = CM_Locate_DevNode(out devInst, deviceInstanceId, CM_LOCATE_DEVNODE_PHANTOM);
                if (result != CR_SUCCESS)
                    return false;

                result = CM_Get_Parent(out int parentInst, devInst, 0);
                if (result != CR_SUCCESS)
                {
                    _logger?.LogDebug("[UsbDeviceFingerprinter] CM_Get_Parent failed ({Err}) for: {Id}", result, deviceInstanceId);
                    return false;
                }

                result = CM_Request_Device_Eject(parentInst, out int vetoType, IntPtr.Zero, 0, 0);
                if (result == CR_SUCCESS)
                    return true;

                _logger?.LogDebug("[UsbDeviceFingerprinter] Parent eject failed ({Err}, veto={Veto}) for: {Id}",
                    result, vetoType, deviceInstanceId);
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] Parent eject exception for: {Id}", deviceInstanceId);
                return false;
            }
        }

        private bool TryEjectViaPnputil(string deviceInstanceId)
        {
            try
            {
                // pnputil /remove-device requires the instance ID in quotes
                // Available on Windows 10 1809+ and Windows Server 2019+
                var psi = new ProcessStartInfo
                {
                    FileName = "pnputil.exe",
                    Arguments = $"/remove-device \"{deviceInstanceId}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var proc = Process.Start(psi);
                if (proc == null) return false;

                proc.WaitForExit(10000);
                if (!proc.HasExited)
                {
                    proc.Kill();
                    return false;
                }

                // Exit code 0 = success
                if (proc.ExitCode == 0)
                    return true;

                var stderr = proc.StandardError.ReadToEnd();
                _logger?.LogDebug("[UsbDeviceFingerprinter] pnputil /remove-device exit={Code} stderr={Err}",
                    proc.ExitCode, stderr);
                return false;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "[UsbDeviceFingerprinter] pnputil fallback exception for: {Id}", deviceInstanceId);
                return false;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid classGuid;
            public int devInst;
            public IntPtr reserved;
        }

        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid ClassGuid,
            string? Enumerator,
            IntPtr hwndParent,
            int Flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            int MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            [Out] System.Text.StringBuilder? DeviceInstanceId,
            int DeviceInstanceIdSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            int Property,
            out int PropertyRegDataType,
            byte[]? PropertyBuffer,
            int PropertyBufferSize,
            out int RequiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);

        //  CfgMgr32 P/Invoke - full PnP device ejection (v1.6.4) 

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Auto)]
        private static extern int CM_Locate_DevNode(
            out int pdnDevInst,
            string pDeviceID,
            int ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Request_Device_Eject(
            int dnDevInst,
            out int pVetoType,
            IntPtr pszVetoName,
            int ulNameLength,
            int ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_Parent(
            out int pdnDevInst,
            int dnDevInst,
            int ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_DevNode_Status(
            out int pulStatus,
            out int pulProblemNumber,
            int dnDevInst,
            int ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Disable_DevNode(
            int dnDevInst,
            int ulFlags);

        private const int CR_SUCCESS = 0;
        private const int CM_LOCATE_DEVNODE_NORMAL = 0x00000000;
        private const int CM_LOCATE_DEVNODE_PHANTOM = 0x00000001;
        private const int CM_PROB_HELD_FOR_EJECT = 47;

        private const int DIGCF_PRESENT = 0x00000002;
        private const int DIGCF_ALLCLASSES = 0x00000004;

        private const int SPDRP_DEVICEDESC = 0x00000000;
        private const int SPDRP_CLASSGUID = 0x00000008;
        private const int SPDRP_SERVICE = 0x00000004;
        private const int SPDRP_FRIENDLYNAME = 0x0000000C;

        private static string GetDeviceProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, int property)
        {
            int requiredSize = 0;
            SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                byte[] buffer = new byte[requiredSize];
                if (SetupDiGetDeviceRegistryProperty(deviceInfoSet, ref deviceInfoData, property, out _, buffer, buffer.Length, out _))
                {
                    return System.Text.Encoding.Unicode.GetString(buffer).TrimEnd('\0');
                }
            }
            return string.Empty;
        }

        private static string GetDeviceInstanceId(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData)
        {
            int requiredSize = 0;
            SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, null, 0, out requiredSize);
            if (requiredSize > 0)
            {
                var sb = new System.Text.StringBuilder(requiredSize);
                if (SetupDiGetDeviceInstanceId(deviceInfoSet, ref deviceInfoData, sb, sb.Capacity, out _))
                {
                    return sb.ToString();
                }
            }
            return string.Empty;
        }

        private List<UsbDevice> GetConnectedUsbDevices()
        {
            var list = new List<UsbDevice>();
            IntPtr deviceInfoSet;
            try
            {
                // setupapi.dll is absent on some heavily stripped Windows images. Guard the very
                // first P/Invoke so a DllNotFoundException degrades to "no USB devices" instead of
                // faulting the constructor (which would take down service startup via DI).
                Guid emptyGuid = Guid.Empty;
                deviceInfoSet = SetupDiGetClassDevs(ref emptyGuid, "USB", IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
            }
            catch
            {
                return list; // USB enumeration facility unavailable - skip gracefully.
            }
            if (deviceInfoSet == (IntPtr)(-1))
            {
                return list;
            }

            try
            {
                var deviceInfoData = new SP_DEVINFO_DATA();
                deviceInfoData.cbSize = Marshal.SizeOf(deviceInfoData);
                int index = 0;

                while (SetupDiEnumDeviceInfo(deviceInfoSet, index, ref deviceInfoData))
                {
                    index++;
                    string instanceId = GetDeviceInstanceId(deviceInfoSet, ref deviceInfoData);
                    if (string.IsNullOrEmpty(instanceId)) continue;

                    string vid = "";
                    string pid = "";
                    string serial = "";

                    var parts = instanceId.Split('\\');
                    if (parts.Length >= 2)
                    {
                        var hardwareId = parts[1];
                        var vidIdx = hardwareId.IndexOf("VID_");
                        if (vidIdx != -1 && hardwareId.Length >= vidIdx + 8)
                        {
                            vid = hardwareId.Substring(vidIdx + 4, 4);
                        }
                        var pidIdx = hardwareId.IndexOf("PID_");
                        if (pidIdx != -1 && hardwareId.Length >= pidIdx + 8)
                        {
                            pid = hardwareId.Substring(pidIdx + 4, 4);
                        }
                    }
                    if (parts.Length >= 3)
                    {
                        serial = parts[2];
                    }

                    string name = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_FRIENDLYNAME);
                    if (string.IsNullOrEmpty(name))
                    {
                        name = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_DEVICEDESC);
                    }
                    // v1.7.2: Do NOT invent "Unknown USB Device" for blank descriptions.
                    // That string was previously treated as failed-enumeration and caused
                    // legitimate devices with empty friendly/device names to be disabled.

                    string classGuidStr = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_CLASSGUID);
                    string service = GetDeviceProperty(deviceInfoSet, ref deviceInfoData, SPDRP_SERVICE);

                    bool isHid = classGuidStr.Equals("{745a17a0-74d3-11d0-b6fe-00a0c90f57da}") ||
                                 service.Equals("HidUsb");

                    bool isMassStorage = service.Equals("USBSTOR");
                    bool isComposite = service.Equals("usbccgp");

                    bool isFailedEnum = IsFailedEnumerationSignals(vid, name);

                    list.Add(new UsbDevice
                    {
                        DeviceId = instanceId,
                        Name = name,
                        Vid = vid,
                        Pid = pid,
                        SerialNumber = serial,
                        IsHid = isHid,
                        IsMassStorage = isMassStorage,
                        IsComposite = isComposite,
                        IsFailedEnumeration = isFailedEnum
                    });
                }
            }
            catch
            {
                // Degrade gracefully
            }
            finally
            {
                SetupDiDestroyDeviceInfoList(deviceInfoSet);
            }

            return list;
        }

        public void Dispose()
        {
            _timer.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
