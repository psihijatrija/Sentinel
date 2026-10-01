// BrowserAppControlGuard - v2.7.1
//
// Protects against a website hijacking / pairing with a local browser-like desktop
// application so it can drive or relay through it. The existing BrowserC2Guard only
// recognizes the mainstream browsers (chrome/msedge/brave/vivaldi/opera/chromium) and
// only the Chrome DevTools "--remote-debugging-port" channel. That leaves three gaps
// that this file closes, WITHOUT touching or knowing about any specific app:
//
//   1. NativeMessagingHostGuard - the canonical page -> extension -> native messaging
//      host -> arbitrary local binary bridge. Baselines the registered native-messaging
//      hosts (registry + on-disk manifests) and flags new / unsigned / user-writable
//      host targets. This is how a web origin reaches out of the browser sandbox to a
//      native app.
//
//   2. LocalControlChannelMonitor - generalizes the CDP-loopback detector: ANY GUI /
//      browser-like process that opens a loopback listener which a NON-browser,
//      NON-parent local process then connects to is a "something is remote-controlling
//      this app locally" signal, regardless of what the port is called.
//
//   3. DangerousLaunchFlagHeuristics - a pure classifier for dangerous browser/app
//      launch flags (--load-extension, --disable-web-security, --proxy-server,
//      --remote-debugging-*, app-mode + persistent profile). Used by a launch-time rule
//      and by the shortcut guard.
//
// All of this is behavioral, userland-only, and observe-until-chain: weak single signals
// are Tier2 LogOnly; kill authority requires a confirmed control channel or multi-signal
// proof. Gated on the always-on hardening posture like the rest of the suite.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure, I/O-free classifier for dangerous browser / browser-like-app launch flags.
    /// Kept static and side-effect-free so it is fully unit-testable (InternalsVisibleTo).
    /// </summary>
    public static class DangerousLaunchFlagHeuristics
    {
        /// <summary>A dangerous launch-flag finding.</summary>
        public enum FlagRisk
        {
            None = 0,
            /// <summary>Weak/ambiguous - observe only (Tier2 LogOnly).</summary>
            Weak,
            /// <summary>Strong control/evasion flag - kill-grade when parent is non-browser.</summary>
            Strong,
        }

        // Flags that grant programmatic control of the browser/app or disable web security.
        // Presence of any STRONG flag means the instance can be driven or has its origin
        // isolation removed - the pairing/relay primitive.
        private static readonly string[] StrongFlags =
        {
            "--remote-debugging-port",
            "--remote-debugging-pipe",
            "--disable-web-security",
            "--load-extension=",
            "--disable-features=isolateorigins,site-per-process",
            "--disable-site-isolation-trials",
        };

        // Flags that are suspicious in combination but common for legitimate automation,
        // kiosks, and packaged web apps - observe only on their own.
        private static readonly string[] WeakFlags =
        {
            "--proxy-server=",
            "--proxy-pac-url=",
            "--app=",
            "--headless",
            "--no-sandbox",
        };

        /// <summary>
        /// Classifies a process command line. Returns the highest risk found and the list of
        /// matched flags. Case-insensitive; whitespace-tolerant.
        /// </summary>
        public static (FlagRisk risk, IReadOnlyList<string> flags) Classify(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine))
                return (FlagRisk.None, Array.Empty<string>());

            var cmd = commandLine!.ToLowerInvariant();
            var matched = new List<string>();
            var risk = FlagRisk.None;

            foreach (var f in StrongFlags)
            {
                if (cmd.Contains(f))
                {
                    matched.Add(f.TrimEnd('='));
                    risk = FlagRisk.Strong;
                }
            }

            foreach (var f in WeakFlags)
            {
                if (cmd.Contains(f))
                {
                    matched.Add(f.TrimEnd('='));
                    if (risk == FlagRisk.None) risk = FlagRisk.Weak;
                }
            }

            // A persistent user-data-dir OUTSIDE Temp, combined with a control flag, is the
            // pattern that survives reboots - upgrade a weak match to strong when paired with
            // an automation profile that is clearly not a throwaway.
            if (risk == FlagRisk.Weak &&
                cmd.Contains("--user-data-dir=") &&
                !cmd.Contains("\\temp\\") && !cmd.Contains("/tmp/"))
            {
                // still weak alone - persistent profile is a corroborator, not a verdict.
                matched.Add("--user-data-dir(persistent)");
            }

            return (risk, matched);
        }

        /// <summary>True if the command line contains any strong control/evasion flag.</summary>
        public static bool HasStrongControlFlag(string? commandLine) =>
            Classify(commandLine).risk == FlagRisk.Strong;
    }

    /// <summary>
    /// Baselines the set of registered browser native-messaging hosts and flags new or
    /// suspicious ones. A native-messaging host is the bridge a browser extension uses to
    /// talk to a native binary; a malicious page + extension can use it to drive a local
    /// app. We look at both the registry registrations (HKCU/HKLM ...\NativeMessagingHosts)
    /// and the on-disk host manifests, resolve each host's target executable, and alert
    /// when the target is unsigned or lives in a user-writable path.
    ///
    /// Runs in the SYSTEM service. Scans every 60s after a 25s settle. Observe-first:
    /// a brand-new host with a signed target in Program Files is Tier2 LogOnly; an unsigned
    /// or user-writable-path target is Tier1 (still LogOnly until chain unless the host is
    /// actively spawned by a browser - handled by LocalControlChannelMonitor correlation).
    /// </summary>
    public sealed class NativeMessagingHostGuard : BackgroundService
    {
        /// <summary>
        /// Whether the guard's proactive scanning/enforcement is permitted. Follows the
        /// always-on hardening posture, so a null/default config still allows it. Exposed
        /// for the default-deny seam test. (InternalsVisibleTo Sentinel.Tests.)
        /// </summary>
        internal static bool MayEnforce(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        private readonly DetectionEngine _detectionEngine;
        private readonly SignerTrustService? _signerTrust;
        private readonly ILogger<NativeMessagingHostGuard> _logger;

        private readonly HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
        private bool _baselineCaptured;
        private readonly ConcurrentDictionary<string, byte> _alerted = new(StringComparer.OrdinalIgnoreCase);

        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(60);

        // Registry roots under which Chromium/Firefox register native-messaging hosts.
        private static readonly string[] RegistrySubKeys =
        {
            @"SOFTWARE\Google\Chrome\NativeMessagingHosts",
            @"SOFTWARE\Microsoft\Edge\NativeMessagingHosts",
            @"SOFTWARE\Chromium\NativeMessagingHosts",
            @"SOFTWARE\Mozilla\NativeMessagingHosts",
            @"SOFTWARE\Mozilla\ManagedStorage", // adjacent Firefox host area
        };

        public NativeMessagingHostGuard(
            DetectionEngine detectionEngine,
            ILogger<NativeMessagingHostGuard> logger,
            SignerTrustService? signerTrust = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _signerTrust = signerTrust;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[NativeMessagingHostGuard] Started - watching browser native-messaging host registrations");
            try { await Task.Delay(TimeSpan.FromSeconds(25), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { Scan(); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[NativeMessagingHostGuard] scan error"); }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void Scan()
        {
            if (!MayEnforce(null))
                return;

            var current = EnumerateHosts();

            if (!_baselineCaptured)
            {
                foreach (var h in current) _baseline.Add(h.Key);
                _baselineCaptured = true;
                _logger.LogInformation("[NativeMessagingHostGuard] Baseline: {N} native-messaging host(s)", _baseline.Count);
                return;
            }

            foreach (var host in current)
            {
                if (_baseline.Contains(host.Key)) continue;      // known at baseline - user's own tooling
                if (_alerted.ContainsKey(host.Key)) continue;    // already reported

                _alerted[host.Key] = 0;
                EvaluateNewHost(host);
            }
        }

        private void EvaluateNewHost(NativeHost host)
        {
            bool signed = !string.IsNullOrEmpty(host.TargetPath) &&
                          (_signerTrust?.IsSignedFile(host.TargetPath!) ?? false);
            bool userWritable = ModuleIdentity.IsUserWritableDrop(host.TargetPath);

            // A new host whose target is unsigned OR sits in a user-writable path is the
            // suspicious case - that is what a page-driven install of a rogue bridge looks
            // like. A signed target in a protected path is normal software installing itself.
            bool suspicious = !signed || userWritable;

            double confidence = suspicious ? (userWritable && !signed ? 0.80 : 0.62) : 0.45;
            var tier = suspicious ? DetectionTier.Tier1Behavioral : DetectionTier.Tier2Indicator;

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Native Messaging: New Host Registered",
                Evidence = $"New native-messaging host '{host.Name}' registered ({host.Source}). " +
                           $"Target: {host.TargetPath ?? "(unresolved)"} " +
                           $"[signed={signed}, userWritable={userWritable}]. " +
                           $"AllowedOrigins: {host.AllowedOrigins}",
                Reasoning = "A browser native-messaging host bridges a web-page-driven extension to a native " +
                            "binary - the canonical way a website reaches out of the browser sandbox to control a " +
                            "local application. A newly registered host pointing at an unsigned executable or one " +
                            "in a user-writable location is consistent with a page/extension planting a rogue bridge " +
                            "to a local app. Observe-first: logged for correlation; a control channel to the target " +
                            "(LocalControlChannelMonitor) or a chain confirms intent." +
                            (suspicious ? "" : " Target is signed and in a protected path - low risk, logged for baseline."),
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "native-messaging-host",
                ProcessId = 0,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = new Dictionary<string, string>
                {
                    ["HostName"] = host.Name,
                    ["Source"] = host.Source,
                    ["TargetPath"] = host.TargetPath ?? "",
                    ["Signed"] = signed.ToString(),
                    ["UserWritable"] = userWritable.ToString(),
                    ["AllowedOrigins"] = host.AllowedOrigins,
                    ["WeakObserveSeed"] = suspicious ? "false" : "true",
                }
            });

            _logger.LogWarning("[NativeMessagingHostGuard] New host '{Name}' -> {Path} (signed={Signed}, userWritable={UW})",
                host.Name, host.TargetPath, signed, userWritable);
        }

        private List<NativeHost> EnumerateHosts()
        {
            var hosts = new List<NativeHost>();

            foreach (var sub in RegistrySubKeys)
            {
                CollectFromHive(Registry.CurrentUser, "HKCU", sub, hosts);
                CollectFromHive(Registry.LocalMachine, "HKLM", sub, hosts);
            }

            return hosts;
        }

        private void CollectFromHive(RegistryKey hive, string hiveName, string subKey, List<NativeHost> into)
        {
            try
            {
                using var key = hive.OpenSubKey(subKey);
                if (key == null) return;

                foreach (var hostName in key.GetSubKeyNames())
                {
                    try
                    {
                        using var hk = key.OpenSubKey(hostName);
                        // The (Default) value is the path to the host's JSON manifest.
                        var manifestPath = hk?.GetValue(null) as string;
                        var host = ReadManifest(hostName, manifestPath, $"{hiveName}\\{subKey}");
                        if (host != null) into.Add(host);
                    }
                    catch { /* single host unreadable - skip */ }
                }
            }
            catch { /* hive/subkey missing - normal */ }
        }

        private static NativeHost? ReadManifest(string hostName, string? manifestPath, string source)
        {
            string? target = null;
            string origins = "";
            try
            {
                if (!string.IsNullOrEmpty(manifestPath) && File.Exists(manifestPath))
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(manifestPath));
                    var root = doc.RootElement;
                    if (root.TryGetProperty("path", out var p)) target = p.GetString();
                    if (root.TryGetProperty("allowed_origins", out var ao) && ao.ValueKind == JsonValueKind.Array)
                        origins = string.Join(",", ao.EnumerateArray().Select(e => e.GetString()).Where(s => s != null));
                    else if (root.TryGetProperty("allowed_extensions", out var ae) && ae.ValueKind == JsonValueKind.Array)
                        origins = string.Join(",", ae.EnumerateArray().Select(e => e.GetString()).Where(s => s != null));

                    // Relative manifest path -> resolve target next to the manifest.
                    if (!string.IsNullOrEmpty(target) && !Path.IsPathRooted(target))
                    {
                        var dir = Path.GetDirectoryName(manifestPath);
                        if (dir != null) target = Path.GetFullPath(Path.Combine(dir, target));
                    }
                }
            }
            catch { /* malformed manifest - still record the registration */ }

            // Key = host name + resolved target, so a re-point of an existing host is a new key.
            return new NativeHost
            {
                Name = hostName,
                TargetPath = target,
                AllowedOrigins = origins,
                Source = source,
                Key = $"{hostName}|{target ?? manifestPath ?? ""}",
            };
        }

        private sealed class NativeHost
        {
            public string Name = "";
            public string? TargetPath;
            public string AllowedOrigins = "";
            public string Source = "";
            public string Key = "";
        }
    }

    /// <summary>
    /// Detects a local process driving a GUI / browser-like application over a loopback
    /// control channel. Generalizes BrowserC2Guard's CDP-specific detector: for every
    /// process that OWNS a listening loopback socket, if a DIFFERENT local process (that is
    /// not the owner's parent and not itself a mainstream browser) has an ESTABLISHED
    /// connection to that loopback port, that is a local remote-control relationship.
    ///
    /// This catches the "website paired with / hijacked a browser-like app" case even when
    /// the app is not one of the known browsers and even when the control port is not the
    /// Chrome "--remote-debugging-port". Observe-first: a single such pairing is Tier2
    /// LogOnly (many legitimate apps use loopback IPC); it escalates only when the client
    /// side is a script host or lives in a user-writable path (the malicious shape).
    ///
    /// Runs in the SYSTEM service, 20s scan, 25s settle, 5-min per-pair cooldown.
    /// </summary>
    public sealed class LocalControlChannelMonitor : BackgroundService
    {
        /// <summary>
        /// Whether loopback control-channel scanning is permitted. Follows the always-on
        /// hardening posture. Exposed for the default-deny seam test.
        /// </summary>
        internal static bool MayEnforce(SentinelConfig? config) =>
            ProductPosture.AllowsProactiveHostLockdown(config);

        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<LocalControlChannelMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly SentinelConfig? _config;

        private readonly ConcurrentDictionary<string, DateTime> _cooldown = new();
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(20);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(5);

        // Mainstream browsers - a client that IS one of these is treated as a normal
        // browser subprocess/tab talking to its own helper, not a hijacker.
        private static readonly HashSet<string> BrowserProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "chrome", "msedge", "msedgewebview2", "brave", "vivaldi", "opera", "chromium",
            "firefox", "iexplore",
        };

        /// <summary>
        /// The kind of loopback pairing, used to separate a benign data-handoff (a page telling
        /// a purpose-built media/torrent client to open a URL/magnet) from a malicious control
        /// channel (a page taking scripting/automation control of a browser). Pure and testable.
        /// </summary>
        internal enum PairingShape
        {
            /// <summary>Server is a mainstream browser being driven over loopback = automation/
            /// remote-control of the browser (CDP-style). The strongest malicious shape.</summary>
            BrowserControlChannel,
            /// <summary>Client is a script host or lives in a user-writable drop = page-dropped
            /// controller. Malicious shape regardless of what the server is.</summary>
            UntrustedController,
            /// <summary>Neither of the above: a signed/in-path client talking to a non-browser
            /// app. Consistent with a data handoff to a legitimate local client. Observe-first.</summary>
            DataHandoff,
        }

        /// <summary>
        /// Classifies a loopback pairing by behavior only (never by domain). A browser as the
        /// driven server is a control channel; a script-host / user-writable client is an
        /// untrusted controller; anything else is a benign-shaped data handoff.
        /// </summary>
        internal static PairingShape ClassifyPairing(
            string serverName, bool clientScriptHost, bool clientUserWritable)
        {
            var serverLeaf = StringNet48.ReplaceIgnoreCase(serverName ?? "", ".exe", "");
            if (BrowserProcessNames.Contains(serverLeaf))
                return PairingShape.BrowserControlChannel;
            if (clientScriptHost || clientUserWritable)
                return PairingShape.UntrustedController;
            return PairingShape.DataHandoff;
        }

        /// <summary>
        /// Aggravator only: true if <paramref name="origins"/> (config-supplied risky pairing
        /// origins) is non-empty and any entry is a case-insensitive suffix of the evidence
        /// string (e.g. a resolved URL/host in metadata). NEVER a verdict on its own - callers
        /// use it only to raise confidence / lower the chain threshold once a behavioral
        /// pairing shape has already been established.
        /// </summary>
        internal static bool MatchesRiskyOrigin(string? evidenceHost, IEnumerable<string>? origins)
        {
            if (string.IsNullOrEmpty(evidenceHost) || origins == null) return false;
            foreach (var o in origins)
            {
                if (string.IsNullOrWhiteSpace(o)) continue;
                if (evidenceHost!.IndexOf(o.Trim(), StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        // Common well-known loopback services we should not treat as control ports.
        private static readonly HashSet<int> BenignLoopbackPorts = new()
        {
            135, 445, 5040, 5354, 5355, 27015, 27036, // RPC/SMB/mDNS/Steam
        };

        public LocalControlChannelMonitor(
            DetectionEngine detectionEngine,
            ILogger<LocalControlChannelMonitor> logger,
            ProcessAncestryCache? ancestry = null,
            SentinelConfig? config = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
            _config = config;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[LocalControlChannelMonitor] Started - loopback control-channel pairing detection");
            try { await Task.Delay(TimeSpan.FromSeconds(25), ct); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { Scan(); }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[LocalControlChannelMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void Scan()
        {
            if (!MayEnforce(null))
                return;

            var rows = GetTcpTable();
            int myPid = System.Net48Environment.ProcessId;

            // 1. Map loopback listeners: port -> owning pid.
            var listeners = new Dictionary<int, int>();
            foreach (var r in rows)
            {
                if (r.State != MIB_TCP_STATE_LISTEN) continue;
                if (!IsLoopback(r.LocalAddr)) continue;
                if (BenignLoopbackPorts.Contains(r.LocalPort)) continue;
                if (r.OwningPid <= 4) continue;
                listeners[r.LocalPort] = r.OwningPid;
            }
            if (listeners.Count == 0) return;

            // 2. Find established loopback connections to those listener ports from a
            //    different, non-browser, non-parent local process.
            foreach (var r in rows)
            {
                if (r.State != MIB_TCP_STATE_ESTAB) continue;
                if (!IsLoopback(r.RemoteAddr)) continue;
                if (!listeners.TryGetValue(r.RemotePort, out var serverPid)) continue;
                if (r.OwningPid <= 4 || r.OwningPid == myPid) continue;

                int clientPid = r.OwningPid;
                if (clientPid == serverPid) continue;            // self-connection
                if (IsParentOf(clientPid, serverPid) || IsParentOf(serverPid, clientPid))
                    continue;                                    // parent<->child helper: normal

                var (clientName, clientPath) = ProtocolProcessLookup.Resolve(clientPid, _ancestry);
                if (BrowserProcessNames.Contains(StringNet48.ReplaceIgnoreCase(clientName, ".exe", "")))
                    continue;                                    // browser tab/subprocess: normal

                var (serverName, serverPath) = ProtocolProcessLookup.Resolve(serverPid, _ancestry);

                Evaluate(serverPid, serverName, serverPath, clientPid, clientName, clientPath, r.RemotePort);
            }
        }

        private void Evaluate(
            int serverPid, string serverName, string? serverPath,
            int clientPid, string clientName, string? clientPath, int port)
        {
            string key = $"{clientPid}:{serverPid}:{port}";
            var now = DateTime.UtcNow;
            if (_cooldown.TryGetValue(key, out var last) && now - last < Cooldown) return;
            _cooldown[key] = now;
            if (_cooldown.Count > 500) PruneCooldown(now);

            // Behavioral discriminator (v2.7.6): separate a benign data handoff (a page telling
            // a purpose-built local client to open a URL/magnet) from a malicious control
            // channel (a page taking scripting/automation control of a browser).
            bool clientScriptHost = UserlandProtocolHeuristics.IsScriptHost(clientName);
            bool clientUserWritable = ModuleIdentity.IsUserWritableDrop(clientPath);
            var shape = ClassifyPairing(serverName, clientScriptHost, clientUserWritable);

            // BrowserControlChannel: a browser is the DRIVEN server = automation/remote-control
            //   of the browser itself (session theft / relay). Malicious shape even if the
            //   client binary is signed and in-path - the control relationship is the harm.
            // UntrustedController: page-dropped script-host / user-writable controller.
            // DataHandoff: signed/in-path client -> non-browser app. Observe-first (a torrent/
            //   media client being handed a magnet/URL looks exactly like this).
            bool suspicious = shape != PairingShape.DataHandoff;

            double confidence =
                shape == PairingShape.BrowserControlChannel ? 0.82 :
                shape == PairingShape.UntrustedController   ? (clientScriptHost && clientUserWritable ? 0.80 : 0.66) :
                                                              0.45;

            // Aggravator ONLY: a configured risky pairing origin never fires on its own. It
            // only sharpens an already-established behavioral signal - raising confidence and
            // nudging an observe-first DataHandoff up to a Tier2 indicator (still LogOnly, never
            // an autonomous action). Behavior stays authoritative.
            string evidenceHost = $"{serverName} {serverPath} {clientName} {clientPath}";
            bool riskyOrigin = MatchesRiskyOrigin(evidenceHost, _config?.RiskyPairingOrigins);
            if (riskyOrigin)
                confidence = Math.Min(0.95, confidence + 0.10);

            var tier = (suspicious || riskyOrigin)
                ? DetectionTier.Tier1Behavioral
                : DetectionTier.Tier2Indicator;
            // A risky-origin match alone (DataHandoff shape) must not reach kill grade: it is a
            // Tier2 indicator, not a Tier1 behavioral terminal.
            if (!suspicious && riskyOrigin)
                tier = DetectionTier.Tier2Indicator;

            string shapeDesc =
                shape == PairingShape.BrowserControlChannel ? "browser driven over a loopback control channel (automation/remote-control of the browser)" :
                shape == PairingShape.UntrustedController   ? "page-dropped controller (script host or user-writable path) driving the app" :
                                                              "signed/in-path client handing data to a non-browser local app (data-handoff shape)";

            _ = _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Local Control Channel: App Driven Over Loopback",
                Evidence = $"Process '{clientName}' (PID {clientPid}, path {clientPath ?? "?"}) is connected to a " +
                           $"loopback control port {port} owned by '{serverName}' (PID {serverPid}, path {serverPath ?? "?"}). " +
                           $"Shape: {shapeDesc}." +
                           (riskyOrigin ? " A configured risky pairing origin was present (aggravator only)." : ""),
                Reasoning = "A local process is driving another GUI/browser-like application over a loopback socket. " +
                            "The differentiator is behavioral, not the site: driving a browser over a control channel " +
                            "is remote-control/session-theft shape; a script-host or user-writable controller is a " +
                            "page-dropped driver; a signed in-path client talking to a non-browser app is a benign data " +
                            "handoff (e.g. a page handing a magnet/URL to a media client). Browser tabs/subprocesses and " +
                            "parent-child helpers are excluded. Observe-first: the pairing is logged; a credential-store " +
                            "read or a chain confirms intent before any action. Risky-origin config is an aggravator only " +
                            "and never authorizes action on its own.",
                Confidence = confidence,
                Tier = tier,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = clientName,
                ProcessId = clientPid,
                SignalType = SignalType.NetworkC2,
                Metadata = new Dictionary<string, string>
                {
                    ["ServerName"] = serverName,
                    ["ServerPid"] = serverPid.ToString(),
                    ["ServerPath"] = serverPath ?? "",
                    ["ClientPath"] = clientPath ?? "",
                    ["LoopbackPort"] = port.ToString(),
                    ["PairingShape"] = shape.ToString(),
                    ["ClientScriptHost"] = clientScriptHost.ToString(),
                    ["ClientUserWritable"] = clientUserWritable.ToString(),
                    ["RiskyOriginAggravator"] = riskyOrigin.ToString(),
                    ["WeakObserveSeed"] = suspicious ? "false" : "true",
                }
            });

            _logger.LogWarning("[LocalControlChannelMonitor] {Client} (PID {CPid}) -> loopback :{Port} of {Server} (PID {SPid})",
                clientName, clientPid, port, serverName, serverPid);
        }

        private void PruneCooldown(DateTime now)
        {
            foreach (var kv in _cooldown)
                if (now - kv.Value > Cooldown) _cooldown.TryRemove(kv.Key, out _);
        }

        private bool IsParentOf(int parentPid, int childPid)
        {
            try
            {
                if (_ancestry != null)
                {
                    var (cachedParent, _) = _ancestry.GetParent(childPid);
                    if (cachedParent == parentPid) return true;
                }
            }
            catch { }
            return false;
        }

        private static bool IsLoopback(uint addr) =>
            // 127.0.0.0/8 in network byte order: low byte == 127
            (addr & 0xFF) == 127;

        //  TCP table 

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        private const uint MIB_TCP_STATE_LISTEN = 2;
        private const uint MIB_TCP_STATE_ESTAB = 5;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder,
            uint ulAf, uint tableClass, uint reserved);

        private struct TcpRow
        {
            public uint State;
            public uint LocalAddr;
            public int LocalPort;
            public uint RemoteAddr;
            public int RemotePort;
            public int OwningPid;
        }

        private static List<TcpRow> GetTcpTable()
        {
            var results = new List<TcpRow>();
            int size = 0;
            const uint AF_INET = 2;
            const uint TCP_TABLE_OWNER_PID_ALL = 5;

            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (size == 0) return results;

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buffer, ref size, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return results;

                int count = Marshal.ReadInt32(buffer);
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                    rowPtr = IntPtr.Add(rowPtr, rowSize);

                    results.Add(new TcpRow
                    {
                        State = row.state,
                        LocalAddr = row.localAddr,
                        LocalPort = (int)(((row.localPort & 0xFF) << 8) | ((row.localPort >> 8) & 0xFF)),
                        RemoteAddr = row.remoteAddr,
                        RemotePort = (int)(((row.remotePort & 0xFF) << 8) | ((row.remotePort >> 8) & 0xFF)),
                        OwningPid = (int)row.owningPid,
                    });
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return results;
        }
    }
}
