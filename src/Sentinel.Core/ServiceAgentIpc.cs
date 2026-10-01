using System;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// v2.0 RT-HIGH-4 - Authenticated local named-pipe IPC between Service (SYSTEM) and Agent (user).
    ///
    /// Auth model:
    ///   1. Service generates a random 32-byte token at start, writes
    ///      %ProgramData%\Sentinel\Secure\.ipc_token (SYSTEM full, Authenticated Users read).
    ///   2. Client proves possession via HMAC-SHA256 over timestamp|nonce|op|body.
    ///   3. 60-second timestamp window blocks replay.
    ///
    /// Ops: ping / ops / health (read-only) plus scan / scan_status (on-demand audit).
    /// No ActiveResponse toggle over IPC.
    /// </summary>
    public static class ServiceAgentIpc
    {
        public const string PipeName = "SentinelIpc-v2";
        public const string ProtocolVersion = "2.0";
        private static readonly TimeSpan MaxSkew = TimeSpan.FromSeconds(60);

        /// <summary>v2.0.4: Expose MaxSkew for nonce pruning in IpcHost.</summary>
        internal static TimeSpan MaxSkewInternal => MaxSkew;

        // v2.0.4 MED-5: Instance-unique pipe name suffix derived from machine GUID.
        // Prevents fingerprinting via static pipe name while remaining consistent across reboots.
        private static readonly Lazy<string> _instancePipeName = new(() =>
        {
            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Cryptography");
                var guid = key?.GetValue("MachineGuid")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(guid))
                {
                    using var sha = SHA256.Create();
                    var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(guid + "-SentinelIpc"));
                    return PipeName + "-" + BitConverter.ToString(hash, 0, 4).Replace("-", "").ToLowerInvariant();
                }
            }
            catch { }
            return PipeName;
        });

        /// <summary>
        /// v2.0.4: Returns machine-specific pipe name (static base + 8-char hex suffix from MachineGuid).
        /// </summary>
        public static string InstancePipeName => _instancePipeName.Value;

        public static string TokenPath
        {
            get
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                return Path.Combine(programData, "Sentinel", "Secure", ".ipc_token");
            }
        }

        public static byte[]? TryLoadToken()
        {
            try
            {
                var path = TokenPath;
                if (!File.Exists(path)) return null;
                var bytes = File.ReadAllBytes(path);
                return bytes.Length == 32 ? bytes : null;
            }
            catch
            {
                return null;
            }
        }

        public static byte[] EnsureServerToken()
        {
            var path = TokenPath;
            var dir = Path.GetDirectoryName(path)!;
            if (!Directory.Exists(dir))
                Directory.CreateDirectory(dir);

            // Lock directory ACL to SYSTEM + Admins (prevent creation-time token read by non-admins)
            LockDirectoryAcl(dir);

            if (File.Exists(path))
            {
                try
                {
                    var existing = File.ReadAllBytes(path);
                    if (existing.Length == 32)
                    {
                        LockTokenAcl(path);
                        return existing;
                    }
                }
                catch { }
            }

            var token = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(token);

            // v2.0.3 RT-MED-1: Atomic token write - create temp file with restricted ACL
            // BEFORE writing bytes, then rename into place. Eliminates the window where
            // the token file exists with inherited (potentially world-readable) permissions.
            var tempPath = path + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp";
            try
            {
                // Create file with explicit restricted ACL from the start
                var security = CreateTokenFileSecurity();
                using (var fs = new FileStream(
                    tempPath,
                    FileMode.CreateNew,
                    FileSystemRights.Write,
                    FileShare.None,
                    4096,
                    FileOptions.None,
                    security))
                {
                    fs.Write(token, 0, token.Length);
                    fs.Flush(true);
                }

                // Atomic replace: if target exists (corrupt/short), delete first
                if (File.Exists(path))
                    File.Delete(path);
                File.Move(tempPath, path);

                // Ensure final ACL is correct (Move preserves source ACL on same volume)
                LockTokenAcl(path);
            }
            catch
            {
                // Fallback: direct write + immediate ACL lock (original behavior)
                try { File.Delete(tempPath); } catch { }
                File.WriteAllBytes(path, token);
                LockTokenAcl(path);
            }

            return token;
        }

        /// <summary>
        /// v2.0.3 / v2.0.8: Build a FileSecurity descriptor for the token file BEFORE creation.
        /// SYSTEM=Full, Admins=Full, Interactive=Read (not all Authenticated Users).
        /// </summary>
        private static FileSecurity CreateTokenFileSecurity()
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);

            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl, AccessControlType.Allow));

            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                admins, FileSystemRights.FullControl, AccessControlType.Allow));

            var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                interactive, FileSystemRights.Read, AccessControlType.Allow));

            return security;
        }

        /// <summary>
        /// v2.0.3 / v2.0.8: Lock Secure directory to SYSTEM + Admins only.
        /// v2.0.8: Removed Authenticated Users from the directory - listing Secure
        /// must not be possible for standard users (entropy / machine_secret live here).
        /// Token file gets a separate Interactive-user read ACE via <see cref="LockTokenAcl"/>.
        /// </summary>
        private static void LockDirectoryAcl(string dirPath)
        {
            try
            {
                var dirInfo = new DirectoryInfo(dirPath);
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));

                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ServiceAgentIpc] LockDirectoryAcl failed: {ex.Message}");
            }
        }

        /// <summary>
        /// SYSTEM + Admins full; Interactive Users read (tray Agent in console session).
        /// v2.0.8: No longer grants Authenticated Users - service accounts and non-interactive
        /// malware cannot read the IPC token for recon of ops/health.
        /// </summary>
        public static void LockTokenAcl(string path)
        {
            try
            {
                var fi = new FileInfo(path);
                var security = fi.GetAccessControl();
                security.SetAccessRuleProtection(true, false);
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    security.RemoveAccessRuleAll(rule);

                var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    system, FileSystemRights.FullControl, AccessControlType.Allow));

                var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    admins, FileSystemRights.FullControl, AccessControlType.Allow));

                // Interactive logon sessions only (S-1-5-4) - the human desktop Agent
                var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    interactive, FileSystemRights.Read, AccessControlType.Allow));

                fi.SetAccessControl(security);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[ServiceAgentIpc] LockTokenAcl failed for '{path}': {ex.Message}");
            }
        }

        public static string Sign(byte[] token, string payload)
        {
            using var hmac = new HMACSHA256(token);
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        public static bool Verify(byte[] token, string payload, string? providedHex)
        {
            if (string.IsNullOrEmpty(providedHex) || providedHex!.Length != 64)
                return false;
            var expected = Sign(token, payload);
            return SecurityValidation.SecureCompare(
                Encoding.ASCII.GetBytes(expected),
                Encoding.ASCII.GetBytes(providedHex.ToLowerInvariant()));
        }

        public static bool IsTimestampFresh(long unixSeconds)
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return Math.Abs(now - unixSeconds) <= (long)MaxSkew.TotalSeconds;
        }

        public static string BuildAuthPayload(long ts, string nonce, string op, string body)
            => $"{ts}|{nonce}|{op}|{body}";
    }

    /// <summary>Service-side named pipe host (SYSTEM).</summary>
    public sealed class ServiceAgentIpcHost : BackgroundService
    {
        private readonly SentinelMetrics _metrics;
        private readonly MonitorRegistry? _registry;
        private readonly WeightedCorrelationConfig _weighted;
        private readonly Plugins.PluginRegistry _plugins;
        private readonly ScanEngine _scanEngine;
        private readonly ILogger<ServiceAgentIpcHost> _logger;
        private byte[] _token = Array.Empty<byte>();

        // v2.0.4 CRIT-1: Server-side nonce tracking to prevent replay attacks within the 60s window.
        // Bounded to MaxNonceEntries; oldest entries pruned when capacity reached.
        private const int MaxNonceEntries = 2048;
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, long> _usedNonces = new();
        private long _lastNoncePruneTs;

        // Cache last scan result so the dashboard can poll for it
        private ScanResult? _lastScanResult;

        public ServiceAgentIpcHost(
            SentinelMetrics metrics,
            WeightedCorrelationConfig weighted,
            Plugins.PluginRegistry plugins,
            ScanEngine scanEngine,
            ILogger<ServiceAgentIpcHost> logger,
            MonitorRegistry? registry = null)
        {
            _metrics = metrics;
            _weighted = weighted;
            _plugins = plugins;
            _scanEngine = scanEngine;
            _logger = logger;
            _registry = registry;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                _token = ServiceAgentIpc.EnsureServerToken();
                _logger.LogInformation("[IPC] Named pipe host ready ({Pipe})", ServiceAgentIpc.InstancePipeName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[IPC] Failed to create IPC token - host disabled");
                return;
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;
                try
                {
                    pipe = CreatePipe();
                    await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                    await HandleClientAsync(pipe, stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[IPC] Client session error");
                }
                finally
                {
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        private static NamedPipeServerStream CreatePipe()
        {
            var security = new PipeSecurity();
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            security.AddAccessRule(new PipeAccessRule(
                system, PipeAccessRights.FullControl, AccessControlType.Allow));
            var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
            security.AddAccessRule(new PipeAccessRule(
                interactive, PipeAccessRights.ReadWrite, AccessControlType.Allow));
            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            security.AddAccessRule(new PipeAccessRule(
                admins, PipeAccessRights.ReadWrite, AccessControlType.Allow));

            return new NamedPipeServerStream(
                ServiceAgentIpc.InstancePipeName,
                PipeDirection.InOut,
                2,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                0,
                0,
                security);
        }

        private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
        {
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };

            // One request per connection (simple + avoids session fixation).
            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(line))
            {
                await writer.WriteLineAsync("{\"ok\":false,\"error\":\"empty\"}").ConfigureAwait(false);
                return;
            }

            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                var op = root.TryGetProperty("op", out var opEl) ? opEl.GetString() ?? "" : "";
                var ts = root.TryGetProperty("ts", out var tsEl) ? tsEl.GetInt64() : 0;
                var nonce = root.TryGetProperty("nonce", out var nEl) ? nEl.GetString() ?? "" : "";
                var sig = root.TryGetProperty("sig", out var sEl) ? sEl.GetString() : null;
                var body = root.TryGetProperty("body", out var bEl) ? (bEl.ValueKind == JsonValueKind.String ? bEl.GetString() ?? "" : bEl.GetRawText()) : "";

                if (!ServiceAgentIpc.IsTimestampFresh(ts) || string.IsNullOrEmpty(nonce) || nonce.Length < 8)
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"auth_freshness\"}").ConfigureAwait(false);
                    return;
                }

                var payload = ServiceAgentIpc.BuildAuthPayload(ts, nonce, op, body);
                if (!ServiceAgentIpc.Verify(_token, payload, sig))
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"auth_sig\"}").ConfigureAwait(false);
                    return;
                }

                // v2.0.4 CRIT-1: Reject replayed nonces within the timestamp window.
                if (!TryConsumeNonce(nonce, ts))
                {
                    await writer.WriteLineAsync("{\"ok\":false,\"error\":\"auth_replay\"}").ConfigureAwait(false);
                    return;
                }

                string response;
                switch (op.ToLowerInvariant())
                {
                    case "ping":
                        response = JsonSerializer.Serialize(new
                        {
                            ok = true,
                            protocol = ServiceAgentIpc.ProtocolVersion,
                            version = ProductInfo.Version,
                            pong = true
                        });
                        break;
                    case "ops":
                        _metrics.TickRates();
                        var snap = _metrics.CreateSnapshot();
                        snap.ProductVersion = ProductInfo.Version;
                        snap.WeightedCorrelationEnabled = _weighted.Enabled;
                        snap.WeightedThreshold = _weighted.Threshold;
                        snap.PluginCount = _plugins.TotalCount;
                        if (_registry != null)
                        {
                            var st = _registry.GetStats();
                            snap.RegisteredMonitors = st.TotalRegistered;
                            snap.RunningMonitors = st.Running;
                        }
                        response = JsonSerializer.Serialize(new { ok = true, ops = snap });
                        break;
                    case "health":
                        var stats = _registry?.GetStats();
                        response = JsonSerializer.Serialize(new
                        {
                            ok = true,
                            version = ProductInfo.Version,
                            monitorsRegistered = stats?.TotalRegistered ?? 0,
                            monitorsRunning = stats?.Running ?? 0,
                            monitorsFailed = stats?.Failed ?? 0,
                            plugins = _plugins.TotalCount
                        });
                        break;
                    case "scan":
                        // Trigger a one-time system scan (non-blocking - returns immediately)
                        if (_scanEngine.IsRunning)
                        {
                            response = JsonSerializer.Serialize(new { ok = true, status = "already_running" });
                        }
                        else
                        {
                            _ = Task.Run(async () =>
                            {
                                _lastScanResult = await _scanEngine.RunFullScanAsync().ConfigureAwait(false);
                            });
                            response = JsonSerializer.Serialize(new { ok = true, status = "started" });
                        }
                        break;
                    case "scan_status":
                        // Return scan progress/results
                        if (_scanEngine.IsRunning)
                        {
                            response = JsonSerializer.Serialize(new { ok = true, status = "running" });
                        }
                        else if (_lastScanResult != null)
                        {
                            response = JsonSerializer.Serialize(new
                            {
                                ok = true,
                                status = "completed",
                                result = _lastScanResult
                            });
                        }
                        else
                        {
                            response = JsonSerializer.Serialize(new { ok = true, status = "idle" });
                        }
                        break;
                    default:
                        response = "{\"ok\":false,\"error\":\"unknown_op\"}";
                        break;
                }

                await writer.WriteLineAsync(response).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[IPC] Bad request");
                await writer.WriteLineAsync("{\"ok\":false,\"error\":\"bad_request\"}").ConfigureAwait(false);
            }
        }

        /// <summary>
        /// v2.0.4 CRIT-1: Returns true if the nonce has not been seen before within the replay window.
        /// Prunes expired entries periodically to bound memory.
        /// </summary>
        private bool TryConsumeNonce(string nonce, long requestTs)
        {
            // Try to add the nonce; if it already exists, it's a replay
            if (!_usedNonces.TryAdd(nonce, requestTs))
                return false;

            // Periodic pruning: remove nonces older than MaxSkew window
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var lastPrune = Interlocked.Read(ref _lastNoncePruneTs);
            if (now - lastPrune > 30 && Interlocked.CompareExchange(ref _lastNoncePruneTs, now, lastPrune) == lastPrune)
            {
                var cutoff = now - (long)ServiceAgentIpc.MaxSkewInternal.TotalSeconds;
                foreach (var kvp in _usedNonces)
                {
                    if (kvp.Value < cutoff)
                        _usedNonces.TryRemove(kvp.Key, out _);
                }
                // Hard cap to prevent unbounded growth under DoS
                if (_usedNonces.Count > MaxNonceEntries)
                {
                    var oldest = _usedNonces.OrderBy(x => x.Value).Take(_usedNonces.Count - MaxNonceEntries);
                    foreach (var kvp in oldest)
                        _usedNonces.TryRemove(kvp.Key, out _);
                }
            }

            return true;
        }
    }

    /// <summary>Agent-side client (user session).</summary>
    public static class ServiceAgentIpcClient
    {
        public static async Task<string?> RequestAsync(string op, string body = "", int timeoutMs = 3000)
        {
            var token = ServiceAgentIpc.TryLoadToken();
            if (token == null) return null;

            try
            {
                using var pipe = new NamedPipeClientStream(
                    ".", ServiceAgentIpc.InstancePipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
                var connectTask = pipe.ConnectAsync(timeoutMs);
                await connectTask.ConfigureAwait(false);
                if (!pipe.IsConnected) return null;

                var ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var nonce = Guid.NewGuid().ToString("N");
                var payload = ServiceAgentIpc.BuildAuthPayload(ts, nonce, op, body);
                var sig = ServiceAgentIpc.Sign(token, payload);

                var req = JsonSerializer.Serialize(new
                {
                    op,
                    ts,
                    nonce,
                    sig,
                    body
                });

                using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, leaveOpen: true) { AutoFlush = true };
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, leaveOpen: true);
                await writer.WriteLineAsync(req).ConfigureAwait(false);
                return await reader.ReadLineAsync().ConfigureAwait(false);
            }
            catch
            {
                return null;
            }
        }

        /// <summary>Synchronous helper for STA Agent UI.</summary>
        public static string? Request(string op, string body = "", int timeoutMs = 3000)
        {
            try
            {
                return RequestAsync(op, body, timeoutMs).GetAwaiter().GetResult();
            }
            catch
            {
                return null;
            }
        }
    }
}
