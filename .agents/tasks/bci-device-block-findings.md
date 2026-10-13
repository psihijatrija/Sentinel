# BCI / EEG Neural-Input Device Block — Findings Report

**Mode:** READ-ONLY investigation. No source code was modified.
**Project:** Sentinel (userland Windows EDR, .NET Framework 4.8 / `net48-windows`, C#) at `e:\Gorstak\Sentinel`.
**Version at time of investigation:** `version.txt` = `3.0.1`.
**Goal:** Determine exactly how to add a reversible device-installation DENY policy for EEG/BCI neural-input peripherals plus an observe-only (Tier2/LogOnly) detection, reusing Sentinel's existing mechanisms. Posture is deny-by-default: the user owns no BCI device, so any BCI/EEG device that attempts to connect must be prevented from binding.

---

## 1. Summary answer (read this first)

- **How Sentinel applies host device/registry policy today:** two mechanisms, both userland.
  1. **Direct HKLM registry writes** via `Microsoft.Win32.Registry.LocalMachine.CreateSubKey(...)` wrapped in the private helpers `HardeningModule.SetRegistryDword` / `SetRegistryString` / `SetRegistryDwordCurrentUser`, and for multi-value lists the ASR pattern writes string/multi-string values directly under a Policy-hive key (`ApplyAsrRules` / `ApplyAsrOnlyExclusions`). This is the dominant pattern and is the right insertion point for a device-install deny.
  2. **LGPO.exe + GSecurity.inf** via `HardeningModule.ApplyLgpoSecurityPolicy()` — a `Process.Start` of the shipped `LGPO.exe` applying a `.inf` security template. This path is for the SECEDIT/security-template class of settings, is coarse, and is **not** the right vehicle for a curated device-install deny list.
- **There is currently NO handling of `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`** anywhere in `src\` (grep for `DeviceInstall`, `DenyDeviceIDs`, `DenyDeviceClasses`, `DenyUnspecified`, `Restrictions` returns no matches). The DeviceInstall-Restrictions mechanism would be net-new, but it fits cleanly into the existing ASR-style registry-policy pattern.
- **How devices are detected today:** `UsbDeviceFingerprinter` enumerates present USB devices via SetupAPI (`SetupDiGetClassDevs("USB", ...)`), parses VID/PID/serial from the instance ID, classifies HID / mass-storage / composite via class GUID + service name, and emits `DetectionEvent`s through `DetectionEngine.EmitAsync`. It already has a trusted-VID:PID allowlist concept but **no deny concept**. This is the detection half to reuse.
- **Recommended design:** a new `NeuralInterfaceDeviceGuard` (a `BackgroundService` registered in a monitor group) that (a) writes a reversible deny policy under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` using the same `CreateSubKey`/`SetValue` idiom as `ApplyAsrRules`, with a `ReleaseNeuralInterfaceDenyPolicy()` teardown wired into `ReleaseUserWorkSurface()` and a self-heal guard mirroring `AsrPolicyGuard`; and (b) emits a **Tier2Indicator / LogOnly** `DetectionEvent` when a matching device is observed, reusing `UsbDeviceFingerprinter`'s enumeration + emission shape.
- **Constraint fit:** This is an HKLM policy write with no kernel driver and no destructive device-stack teardown — it is userland-applicable and reversible, which satisfies the project's hard constraints. **Destructive driver force-removal / device-stack teardown is NOT the sanctioned approach**; the policy-restriction approach is.
- **Over-blocking warning (critical):** several BCI vendors ship on **shared** USB-serial bridge chips (Silicon Labs CP210x `VID_10C4`, FTDI `VID_0403`). Denying by those VIDs — or by the generic Ports/HIDClass/USB **setup-class** GUID — would block huge amounts of legitimate hardware. The deny set must be **specific `VID_xxxx&PID_xxxx` hardware IDs**, never a shared bridge VID alone and never a generic device class. A pure-BLE/HID headset that presents no distinguishing hardware ID is a documented residual gap that cannot be closed by class without collateral damage.

---

## 2. Evidence — how Sentinel applies & reverts host device/registry policy today

All file/line references are to `e:\Gorstak\Sentinel\src\Sentinel.Core\HardeningModule.cs` unless noted.

### 2.1 Entry points and lifecycle

- `HardeningModule.ApplyOrFail()` is the apply entry point. It calls `ApplyIPSecPolicy()`, `BlockRemoteRpcEphemeralPorts()`, and `ApplyUserSetupScriptsHardening()` on every startup. Hardening is unconditional as of v2.5.5 (`RestrictivePortHardeningEnabled { get => true; set { } }`).
- `ApplyUserSetupScriptsHardening()` is the aggregate host-hardening routine:

  ```csharp
  DisableRemoteAccessServices();
  ApplyRegistryHardening();
  EnforceDepAlwaysOn();
  ApplyLgpoSecurityPolicy();
  ApplyAsrRules();
  ApplyCredentialHardening();
  ApplyBrowserHardening();
  ```

  A new `ApplyNeuralInterfaceDenyPolicy()` call would be added here (or driven from the new guard's `StartAsync`).
- `HardeningModule.ReleaseUserWorkSurface()` is the **revert/teardown** entry point (called on uninstall / work-surface release). It removes only Sentinel-created artifacts (comment: "ONLY removes rules/policies that Sentinel itself created"). It currently calls `RemoveIPSecPolicyIfPresent()`, `RemoveFirewallRuleByName("Sentinel-Block-Remote-RPC-Ephemeral")`, `ReleaseAsrBlockPolicy()`, and `ApplyAsrOnlyExclusions()`. **A new `ReleaseNeuralInterfaceDenyPolicy()` must be added here** so the deny is reverted on uninstall.

### 2.2 The two concrete policy-write mechanisms

**(a) Direct HKLM registry writes — the primary mechanism.** Helper signatures:

```csharp
private static void SetRegistryDword(string subKey, string valueName, int value)   // Registry.LocalMachine.CreateSubKey(subKey, writable:true); key?.SetValue(...DWord)
private static void SetRegistryString(string subKey, string valueName, string value) // ...SetValue(...String)
private static void SetRegistryDwordCurrentUser(string subKey, string valueName, int value) // Registry.CurrentUser
```

Each is wrapped in `try { } catch { }` ("Non-fatal: may lack admin rights"), i.e. fail-soft. `ApplyRegistryHardening()` uses these to write dozens of HKLM policy values, e.g. `SOFTWARE\Policies\Microsoft\Windows\Installer` `AlwaysInstallElevated=0`, `SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars` `EnableRegistrars=0`. This proves Sentinel already writes under `HKLM\SOFTWARE\Policies\Microsoft\Windows\...` — the exact hive the DeviceInstall Restrictions key lives in.

**The ASR list pattern is the closest existing analog to a device deny-list** and should be the template. Key symbols:

- `private const string AsrPolicyRoot = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR";`
- `private const string AsrPolicyRulesKey = AsrPolicyRoot + @"\Rules";`
- `internal static readonly (string Guid, string Name)[] AsrRules = { ... }` — the curated list, declared as a static readonly array of tuples.
- `public static void ApplyAsrRules()` — opens/creates the policy key and writes each list entry:

  ```csharp
  using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(AsrPolicyRulesKey, writable: true);
  if (key == null) return;
  foreach (var (guid, _) in AsrRules)
      key.SetValue(guid, "1", Microsoft.Win32.RegistryValueKind.String);
  ```

- `public static void ApplyAsrOnlyExclusions()` writes a **`MultiString`** value (`RegistryValueKind.MultiString`) — proof the codebase already writes REG_MULTI_SZ lists via the Registry API when a policy needs a multi-valued list.
- `public static bool IsAsrPolicyIntact()` — reads the key back and returns false on any missing/wrong value (the self-heal check).
- `public static void ReleaseAsrBlockPolicy()` — opens the key writable and `key.DeleteValue(guid, throwOnMissingValue: false)` for each entry (the symmetric teardown).
- `public static void ReapplyAsrRules() => ApplyAsrRules();` — the re-arm hook called by the guard.

**Self-heal guard pattern:** `AsrPolicyGuard` is registered in `Sentinel.Service\Program.cs` (singleton + Critical-group registration) and documented in `docs\design.md`: every 60s (20s initial delay) it calls `HardeningModule.IsAsrPolicyIntact()`, and on drift re-applies + emits a **Tier1 LogOnly** Anti-Tamper detection. A `NeuralInterfaceDeviceGuard` self-heal should mirror this exactly (periodic `IsNeuralInterfaceDenyPolicyIntact()` → `ReapplyNeuralInterfaceDenyPolicy()` on drift).

**(b) LGPO.exe + GSecurity.inf — secondary, not for this feature.**

```csharp
private static void ApplyLgpoSecurityPolicy()
{
    string baseDir = AppContext.BaseDirectory;
    string lgpoPath = Path.Combine(baseDir, "LGPO.exe");
    string infPath  = Path.Combine(baseDir, "GSecurity.inf");
    if (!File.Exists(lgpoPath) || !File.Exists(infPath)) return;
    var psi = new ProcessStartInfo(lgpoPath, $"/s \"{infPath}\"") { CreateNoWindow = true, UseShellExecute = false, WorkingDirectory = baseDir };
    using var proc = Process.Start(psi);
    proc?.WaitForExit(30000);
}
```

`LGPO.exe` is shipped (found at `src\Sentinel.Core\HardeningResources\LGPO.exe` and in the publish trees). Note a nuance: `ApplyLgpoSecurityPolicy` looks for `LGPO.exe`/`GSecurity.inf` directly in `AppContext.BaseDirectory`, while the files ship under a `HardeningResources\` subfolder — so this path is best-effort and may no-op depending on layout. Regardless, LGPO applies a SECEDIT-style `.inf` and is a poor fit for a curated, retroactive DeviceInstall deny list. **Use direct registry writes (pattern (a)), not LGPO.**

### 2.3 Confirmation: no existing DeviceInstall handling

Grep across `src\**\*.cs` for `DeviceInstall | DenyDeviceIDs | DenyDeviceClasses | DenyUnspecified | Restrictions` → **no matches**. Nothing today touches `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`. The feature is net-new but slots into the ASR-style pattern above.

---

## 3. Evidence — how `UsbDeviceFingerprinter` detects devices and the exact emission shape to reuse

File: `e:\Gorstak\Sentinel\src\Sentinel.Core\UsbDeviceFingerprinter.cs`.

### 3.1 Enumeration & identifiers captured

- `private List<UsbDevice> GetConnectedUsbDevices()` enumerates via SetupAPI:
  - `SetupDiGetClassDevs(ref emptyGuid, "USB", IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES)` (guarded against `DllNotFoundException` on stripped images — degrades to "no devices").
  - Loops `SetupDiEnumDeviceInfo`; reads the instance ID via `SetupDiGetDeviceInstanceId`.
  - Parses the instance ID (`USB\VID_xxxx&PID_xxxx\<serial>`): splits on `\`, extracts the 4-hex **VID** (substring after `VID_`), 4-hex **PID** (after `PID_`), and the third segment as **serial**.
  - Reads device properties via `SetupDiGetDeviceRegistryProperty`: `SPDRP_FRIENDLYNAME` / `SPDRP_DEVICEDESC` (name), `SPDRP_CLASSGUID` (device setup class GUID), `SPDRP_SERVICE` (driver service).
  - Classifies: `isHid = classGuid == "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}" || service == "HidUsb"`; `isMassStorage = service == "USBSTOR"`; `isComposite = service == "usbccgp"`.
- The `UsbDevice` model exposes: `DeviceId` (full instance ID), `Name`, `Vid`, `Pid`, `SerialNumber`, `IsHid`, `IsMassStorage`, `IsComposite`, `IsFailedEnumeration`.
- `internal static string? NormalizeVidPid(string? raw)` normalizes `"0951:1666"`, `"VID_0951&PID_1666"`, `"0951-1666"` → `"0951:1666"` (used for the trusted set and reusable for a deny set).

### 3.2 Allow/deny concept today

- **Allow only.** `_trustedVidPid` (built from `DefaultTrustedUsb` + `SentinelConfig.TrustedUsbDevices`) and `AllowedKeyboardVids` (a static HID VID allowlist: Logitech `046D`, Microsoft `045E`, etc.). There is **no deny list** — new/unknown devices are logged (and only auto-disabled under narrow failed-enumeration / kiosk conditions).
- Response is work-first: HID auto-disable only when `ProductPosture.AllowsProactiveHostLockdown(_config)`; failed-enumeration auto-disable only when `_config.AutoDisableFailedUsbEnumeration` (default **false**).
- Disable/eject helpers exist but are reactive node operations, **not** install prevention: `DisableUsbDevice` (writes `ConfigFlags=1` under `SYSTEM\CurrentControlSet\Enum\<instanceId>`), `EjectUsbDevice` (CfgMgr `CM_Request_Device_Eject` / parent-hub eject / `pnputil /remove-device`). These remove an *already-present* node; they do not stop a device from binding on the next plug-in. That is exactly why a **DeviceInstall deny policy** is the correct complement.

### 3.3 Exact `DetectionEvent` emission shape to reuse

`ProcessNewDevice(UsbDevice dev)` builds and emits:

```csharp
var detection = new DetectionEvent
{
    RuleName = ruleName,                 // e.g. "USB: New Device Connected" / "BadUSB: Unknown HID Device"
    ProcessName = "SentinelService.exe",
    ProcessId = System.Net48Environment.ProcessId,
    Confidence = confidence,
    Tier = tier,                          // DetectionTier.Tier2Indicator or Tier1Behavioral
    AuthorizedResponse = response,        // ResponseAction.LogOnly
    Evidence = evidence,
    Reasoning = "...",
    Metadata = new Dictionary<string, string>
    {
        { "VID", dev.Vid }, { "PID", dev.Pid },
        { "DeviceName", dev.Name ?? "" }, { "Serial", dev.SerialNumber ?? "" },
        { "DeviceId", dev.DeviceId ?? "" },
        { "FailedEnumeration", ... }, { "Disabled", ... }, { "Ejected", ... }, { "Trusted", ... }
    }
};
_ = _detectionEngine.EmitAsync(detection);
```

`DetectionEvent` (defined in `src\Sentinel.Core\Models.cs`) fields relevant to a BCI detection:

- `string RuleName`, `string? RuleId`, `string Evidence`, `string Reasoning`
- `double Confidence`
- `DetectionTier Tier` — enum `{ Tier1Behavioral, Tier2Indicator }`
- `SignalType SignalType` — enum includes `Generic, SuspiciousProcess, AntiTamper, SecurityEvasion, PhantomKeystroke, ...` (no BCI-specific member; use `Generic` or `SecurityEvasion`).
- `TerminalFamily? Family` — leave `null` for an observe-only signal.
- `Dictionary<string,string> Metadata`
- `ResponseAction AuthorizedResponse` — enum `{ LogOnly, NetworkIsolate, RemoveCert, VpnShieldUp, KillProcess, KillProcessTree, Quarantine, ... }`; `KillAuthorized => AuthorizedResponse >= KillProcess`. For BCI detection use **`LogOnly`**, which keeps `KillAuthorized == false`.

Emission API: `DetectionEngine.EmitAsync(DetectionEvent)` — "Direct emission bypassing rules (for monitors that emit detections directly)"; records a metric then calls `HandleDetectionEventAsync`. This is the exact call the BCI guard should use.

### 3.4 Other device-arrival surfaces (hook vs duplicate)

- `UsbDeviceFingerprinter` is a **polling** monitor: constructor baselines connected devices and starts a `System.Threading.Timer` firing `PollUsbDevices` every 30s; new (unbaselined) devices go through `ProcessNewDevice`. It is **not** a `BackgroundService` — it is a self-starting singleton registered in `Sentinel.Service\Program.cs` (`services.AddSingleton<UsbDeviceFingerprinter>();`), injected into `SentinelService.cs`, "registered" via `Reg(nameof(UsbDeviceFingerprinter), MonitorCategory.UserProtection)`, and disposed in the service's disposables array.
- `PhysicalAccessMonitor` (`PhysicalAccessMonitor.cs`) is a `BackgroundService` that snapshots USB **and Bluetooth** devices and reports *new USB/Bluetooth devices after an idle period* as physical-tamper anomalies. It already has Bluetooth-device enumeration (`SnapshotBluetoothDevices`) — relevant because a BLE/HID BCI headset may surface here rather than on the USB enumerator.
- `VolumeMountMonitor` (`VolumeMountMonitor.cs`) handles volume mount/dismount only — not relevant to a neural-input peripheral; do not hook here.

**Recommendation on where to hook:** do **not** bolt BCI logic onto `UsbDeviceFingerprinter.ProcessNewDevice` (it is USB-only, polling, and already dense). Add a dedicated `NeuralInterfaceDeviceGuard` so (1) the policy-apply + self-heal lifecycle lives with it (mirroring `AsrPolicyGuard`), and (2) the observe-only detection can reuse `UsbDeviceFingerprinter`'s enumeration helpers / `NormalizeVidPid` without entangling the two responsibilities. The guard can enumerate the same SetupAPI way and emit via `DetectionEngine.EmitAsync`.

---

## 4. The Windows DeviceInstall Restrictions mechanism as applied through Sentinel's existing registry path

**Hive / key (net-new to Sentinel, standard Windows policy):**
`HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions`

Written exactly like `ApplyAsrRules` — `Registry.LocalMachine.CreateSubKey(..., writable:true)` + `key.SetValue(...)`. All values below are the standard Group-Policy "Prevent installation of devices that match any of these device IDs" / "...device setup classes" value shapes.

### 4.1 Deny by specific hardware ID (RECOMMENDED — precise, low collateral)

Under `...\DeviceInstall\Restrictions`:
- `DenyDeviceIDs` = `1` (DWORD) — enable the device-ID deny list.
- `DenyDeviceIDsRetroactive` = `1` (DWORD) — **make it retroactive** so an already-installed matching device is also blocked (not only future installs). This is the "block it even if it is already present" switch.

Under the subkey `...\DeviceInstall\Restrictions\DenyDeviceIDs`:
- Values named `"1"`, `"2"`, `"3"`, … (REG_SZ), each one a hardware ID string, e.g. `USB\VID_2458&PID_0001`. (Numbered string values, same idiom as a numbered list — analogous to how ASR writes one named value per rule.)

### 4.2 Deny by device setup class (USE SPARINGLY — high collateral risk)

Under `...\DeviceInstall\Restrictions`:
- `DenyDeviceClasses` = `1` (DWORD)
- `DenyDeviceClassesRetroactive` = `1` (DWORD)
Under subkey `...\DeviceInstall\Restrictions\DenyDeviceClasses`:
- Values `"1"`, `"2"`, … (REG_SZ), each a **device setup class GUID** (with braces).

**Do not** use this for generic classes (HIDClass `{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}`, Ports/COM `{4D36E978-E325-11CE-BFC1-08002BE10318}`, USB `{36FC9E60-C465-11CF-8056-444553540000}`) — that over-blocks keyboards, mice, serial adapters, etc. Only a BCI-exclusive setup class GUID (rare) is safe here.

### 4.3 `DenyUnspecified` (NOT recommended for this user)

- `DenyUnspecified` = `1` would block anything **not** explicitly allowed (allow-list-only posture). That is a lockdown far broader than "block BCI devices" and would break arbitrary legitimate peripherals. **Exclude it** from this feature; it contradicts the targeted deny-by-default-for-BCI-only intent.

### 4.4 Reversion on uninstall

Mirror `ReleaseAsrBlockPolicy`: open each key writable and `DeleteValue(..., throwOnMissingValue:false)` for every value Sentinel wrote, then delete the empty `DenyDeviceIDs` / `DenyDeviceClasses` subkeys and the enable/retroactive DWORDs. Wire the call (`ReleaseNeuralInterfaceDenyPolicy()`) into `HardeningModule.ReleaseUserWorkSurface()` next to `ReleaseAsrBlockPolicy()`. Delete only Sentinel-written values (track them by the known hardware-ID set) to honor the v2.0.4 HIGH-5 "only remove what Sentinel created" rule.

### 4.5 Userland applicability — confirmed within hard constraints

This mechanism is **pure HKLM policy registry writes** executed by the Sentinel service (SYSTEM) — no kernel driver, no direct syscalls, no device-stack surgery. It is identical in nature to the ASR/registry hardening Sentinel already performs. It therefore satisfies "userland only" and "no kernel drivers". Enforcement is performed by the Windows PnP manager reading the policy at install time; Sentinel merely writes the policy and self-heals it. (Note: writing these keys requires the service to run elevated/SYSTEM, same as the existing ASR writes; under standard-user it fails soft like `SetRegistryDword`.)

---

## 5. Recommended deny set — with explicit over-blocking callouts

**Rule: deny by specific `VID_xxxx&PID_xxxx` hardware ID, never by a shared bridge VID alone, never by a generic device class.** The exact PIDs below should be CONFIRMED against physical hardware / vendor INF files before shipping; treat them as the starting set, encoded as a `static readonly` string array exactly like `AsrRules`.

| Vendor / device | Starting identifier | Deny by | Over-block risk | Recommendation |
|---|---|---|---|---|
| InteraXon **Muse** (USB dongle variants) | specific `VID&PID` once confirmed | Hardware ID | Low if PID-specific | **Include** by exact `VID_xxxx&PID_xxxx` only. Muse is primarily BLE (see residual gap). |
| **Emotiv** EPOC / USB receiver | specific `VID&PID` (confirm; task's `0x1234` is a known RAT-port decoy value, **not** a verified Emotiv VID — do not ship unverified) | Hardware ID | Low if PID-specific | **Include** by exact hardware ID **after verification**. Do **not** deny the bare VID. |
| **NeuroSky** (ships on Silicon Labs **CP210x**, `VID_10C4`) | `VID_10C4&PID_xxxx` | Hardware ID (full) | **HIGH** if denied by `VID_10C4` alone — CP210x is a generic USB-UART bridge used by countless unrelated devices (dev boards, meters, radios). | **Deny only the full `VID_10C4&PID_<neurosky>` ID.** Explicitly do NOT deny `VID_10C4` or the Ports class. |
| **OpenBCI** (FTDI-based, `VID_0403`) | `VID_0403&PID_xxxx` | Hardware ID (full) | **HIGH** if denied by `VID_0403` alone — FTDI is the single most common USB-serial VID in existence. | **Deny only the full FTDI `VID_0403&PID_<openbci>` ID.** Never the bare VID. |
| **g.tec** (g.USBamp / g.Nautilus) | specific `VID&PID` (confirm) | Hardware ID | Low if PID-specific | **Include** by exact hardware ID after verification. |
| **Wearable Sensing** (DSI series) | specific `VID&PID` (confirm) | Hardware ID | Low if PID-specific | **Include** by exact hardware ID after verification. |

**Explicitly excluded from the deny set (would cause collateral over-blocking):**
- Any bare shared-bridge VID: `VID_10C4` (Silicon Labs CP210x), `VID_0403` (FTDI), `VID_067B` (Prolific), etc. — blocking these breaks generic USB-serial adapters.
- Any generic setup-class GUID: HIDClass, Ports (COM & LPT), USB, Bluetooth. — blocking these breaks keyboards, mice, controllers, serial adapters, and all BT devices.
- `DenyUnspecified=1` — allow-list-only posture; far too broad for this intent.

**Documented residual gap (cannot be closed without collateral damage):** a BCI/EEG headset that connects over **generic Bluetooth LE / standard HID** and presents no vendor-distinguishing hardware ID (e.g. Muse over BLE) **cannot be denied by device class** without also denying every legitimate BLE/HID peripheral. For those, the achievable posture is **observe-only detection** (Section 3 / 6b) plus denying any USB companion dongle by its specific hardware ID. State this limitation plainly in user-facing docs — do not claim a BLE-only headset is "blocked".

---

## 6. Concrete design for `NeuralInterfaceDeviceGuard`

New file: `src\Sentinel.Core\NeuralInterfaceDeviceGuard.cs` (and/or policy methods on `HardeningModule` to keep registry-policy symbols co-located with the ASR pattern). Monitor class placement must follow the constraint "each monitor class lives in the group file it belongs to under `Monitors/`"; a device/physical-protection guard fits the Critical / SystemIntegrity group alongside `AsrPolicyGuard`.

### 6a. Policy half (reversible device-install DENY) — mirrors the ASR symbols

Add to `HardeningModule` (co-located with `AsrRules`/`ApplyAsrRules`):

```csharp
private const string DeviceInstallRestrictionsKey =
    @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";

// Curated, CONFIRMED BCI hardware IDs. Specific VID&PID only — never a shared bridge VID,
// never a generic class GUID. Encoded like AsrRules (static readonly list of tuples).
internal static readonly (string HardwareId, string Name)[] NeuralInterfaceDenyIds =
{
    // ("USB\\VID_xxxx&PID_xxxx", "InteraXon Muse USB"),
    // ("USB\\VID_10C4&PID_xxxx", "NeuroSky (CP210x — full ID only, NOT bare VID_10C4)"),
    // ("USB\\VID_0403&PID_xxxx", "OpenBCI (FTDI — full ID only, NOT bare VID_0403)"),
    // ...confirm against hardware before enabling...
};

public static void ApplyNeuralInterfaceDenyPolicy()
{
    try
    {
        using var root = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DeviceInstallRestrictionsKey, writable: true);
        if (root == null) return;
        root.SetValue("DenyDeviceIDs", 1, Microsoft.Win32.RegistryValueKind.DWord);
        root.SetValue("DenyDeviceIDsRetroactive", 1, Microsoft.Win32.RegistryValueKind.DWord);

        using var list = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(DeviceInstallRestrictionsKey + @"\DenyDeviceIDs", writable: true);
        if (list == null) return;
        int i = 1;
        foreach (var (hwid, _) in NeuralInterfaceDenyIds)
            list.SetValue((i++).ToString(), hwid, Microsoft.Win32.RegistryValueKind.String);
    }
    catch { /* non-fatal, fail-soft like SetRegistryDword */ }
}

public static bool IsNeuralInterfaceDenyPolicyIntact() { /* read back DenyDeviceIDs==1 + every hwid present; mirror IsAsrPolicyIntact */ }
public static void ReapplyNeuralInterfaceDenyPolicy() => ApplyNeuralInterfaceDenyPolicy();

public static void ReleaseNeuralInterfaceDenyPolicy()
{
    // mirror ReleaseAsrBlockPolicy: DeleteValue each numbered hwid (throwOnMissingValue:false),
    // then remove the DenyDeviceIDs subkey + the enable/retroactive DWORDs. Delete only what we wrote.
}
```

- Call `ApplyNeuralInterfaceDenyPolicy()` from `ApplyUserSetupScriptsHardening()` (or the new guard's start) and `ReleaseNeuralInterfaceDenyPolicy()` from `ReleaseUserWorkSurface()`.
- Self-heal: the guard polls `IsNeuralInterfaceDenyPolicyIntact()` on an interval (e.g. 60s like `AsrPolicyGuard`) and calls `ReapplyNeuralInterfaceDenyPolicy()` on drift, emitting a **Tier1 LogOnly** AntiTamper detection (same as the ASR guard's drift behavior).

### 6b. Detection half (observe-only) — reuses the fingerprinter shape

On each enumeration (reusing `SetupDiGetClassDevs("USB", ...)` + `NormalizeVidPid`), when a present device's `VID:PID` (or full hardware ID) matches `NeuralInterfaceDenyIds`, emit:

```csharp
var detection = new DetectionEvent
{
    RuleName = "Neural Interface Device: BCI/EEG Peripheral Observed",
    ProcessName = "SentinelService.exe",
    ProcessId = System.Net48Environment.ProcessId,
    Confidence = 0.60,
    Tier = DetectionTier.Tier2Indicator,          // MUST be Tier2
    AuthorizedResponse = ResponseAction.LogOnly,   // MUST be LogOnly => KillAuthorized == false
    SignalType = SignalType.SecurityEvasion,       // or Generic (no BCI-specific member exists)
    Evidence = $"BCI/EEG neural-input device matched deny set: '{name}' (VID {vid} PID {pid}). " +
               "Device-install deny policy is enforced for this hardware ID.",
    Reasoning = "Deny-by-default BCI posture: user owns no neural-input device. Policy prevents bind; " +
                "this is an observe-only record of the attempted connection.",
    Metadata = new Dictionary<string,string>
    {
        { "VID", vid }, { "PID", pid }, { "HardwareId", hwid },
        { "DeviceName", name }, { "PolicyEnforced", "DeviceInstall/Restrictions/DenyDeviceIDs" }
    }
};
await _detectionEngine.EmitAsync(detection);
```

- **Tier2 + LogOnly is mandatory** (Section 7). The guard's detection half never kills, quarantines, ejects, or disables — the *policy* does the blocking at PnP-install time; the detection is pure telemetry.

### 6c. Wiring (DI)

- Register the guard as a singleton in `Sentinel.Service\Program.cs` (next to `AsrPolicyGuard`), add it to the Critical/SystemIntegrity monitor group registration list, and add it to the disposables array in `SentinelService.cs` — exactly how `AsrPolicyGuard` and `UsbDeviceFingerprinter` are wired. Constructor-inject `DetectionEngine` and `ILogger<NeuralInterfaceDeviceGuard>` (DI required by constraints). Thread `CancellationToken` through any async loop; log every catch at ≥ Debug.

---

## 7. Constraints the guard must satisfy, and confirmation of the sanctioned approach

From `.kiro\steering\constraints.md` and `docs\constraints.md` (v2.5.6 header) and `Sentinel\AGENTS.md`:

- **Userland only — no kernel drivers / no direct syscalls / no self-hiding.** The policy is an HKLM registry write; enforcement is by the Windows PnP manager. **Satisfied.** Destructive device-stack teardown (force-removing drivers, ripping the device stack) would NOT be userland-clean behavior in spirit and is **not** acceptable — the registry-restriction policy is the sanctioned mechanism.
- **Reversible.** `ReleaseNeuralInterfaceDenyPolicy()` wired into `ReleaseUserWorkSurface()`, deleting only Sentinel-written values (honors v2.0.4 HIGH-5 "only remove what Sentinel created"). **Satisfied.**
- **Tier2 can NEVER trigger a response action; Tier2 = LogOnly unconditionally.** The detection half is `Tier2Indicator` + `LogOnly` (`KillAuthorized == false`). The *blocking* is the pre-emptive policy, not a response action fired off a detection — so the observe/act separation is preserved. **Satisfied.**
- **Behavioral signals only for kill authority / observe-first.** The detection grants no kill authority; it is observe-only fuel. The deny policy is a *configuration* applied as part of always-on hardening, not a per-detection kill. **Satisfied.**
- **Adversarial mindset / no attacker-controllable trust.** The deny set is keyed on specific hardware IDs; it is a deny list (not an allow list that an attacker could satisfy by naming). The over-block analysis (Section 5) avoids broad class/VID denies that could be weaponized to brick legitimate hardware. **Satisfied.**
- **No string-built JSON; DI required; CancellationToken threaded; no silent catch; graceful degradation.** The design uses typed `DetectionEvent` + `System.Text.Json` downstream, DI-injected `DetectionEngine`, fail-soft registry writes (like `SetRegistryDword`), and `SetupDiGetClassDevs` guarded against `DllNotFoundException`. **Satisfied by design.**
- **No shelling out for detection/response logic.** Use the Registry API (not `reg.exe`) and SetupAPI/CfgMgr P/Invoke — matching existing code. Do NOT use LGPO.exe for this. **Satisfied.**
- **Versioning (AGENTS.md / workflow.md):** `version.txt` currently `3.0.1`; a release bumps exactly one PATCH via `installer\release.ps1`. The implementer must not jump versions.
- **Monitor placement:** register via a `MonitorGroup`, put the class in the correct `Monitors/` group file; no flat `AddHostedService` and no monolith file (per constraints).

**Conclusion on sanctioned approach:** Yes — a reversible `DeviceInstall\Restrictions` **deny policy** (DenyDeviceIDs + retroactive), applied through Sentinel's existing direct-HKLM-registry pattern (the ASR template) with a self-heal guard and uninstall teardown, plus a Tier2/LogOnly observe-only detection reusing `UsbDeviceFingerprinter`'s enumeration + `DetectionEngine.EmitAsync`, is the correct and constraint-compliant design. Destructive driver removal / device-stack teardown is explicitly NOT sanctioned.

---

## 8. Open items for the implementer (gaps / assumptions)

1. **Confirm real hardware IDs** for Emotiv / Muse / g.tec / Wearable Sensing and the exact NeuroSky (CP210x) and OpenBCI (FTDI) **PIDs** before populating `NeuralInterfaceDenyIds`. The task's `0x1234` for Emotiv is almost certainly a decoy value (it collides with Sentinel's own `RAT_1234` attack-port definition) and must not be shipped unverified.
2. **Elevation:** the deny policy requires SYSTEM/elevated writes (same as ASR). Under standard-user it fails soft — document that full enforcement needs the service.
3. **BLE/HID residual gap** (Section 5) is unavoidable without collateral damage; surface it in user docs rather than overstating coverage.
4. **Decide enforcement default:** given the user's explicit deny-by-default intent, applying the deny unconditionally (like always-on hardening) is consistent; if a config gate is desired, follow the "compiled config only" constraint (disk JSON is not loaded).

*Content was rephrased where it drew on external Windows policy documentation; all code citations are quoted from the repository as read.*
