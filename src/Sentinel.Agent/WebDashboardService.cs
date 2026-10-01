using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Core;

namespace Sentinel.Agent
{
    /// <summary>
    /// Embedded web dashboard served via HttpListener on localhost.
    /// Provides REST API and WebSocket endpoints for the browser-based UI.
    /// The AgentDashboardForm hosts a WebBrowser control pointed at this service.
    /// </summary>
    public sealed class WebDashboardService : BackgroundService
    {
        public const int DefaultPort = 19845;
        public const string DashboardUrl = "http://localhost:19845/";

        /// <summary>
        /// v2.2.0: token is NOT embedded in GET /. Tray opens this URL; JS stores the
        /// token in sessionStorage and strips it from the address bar.
        /// </summary>
        public static string? SessionToken { get; private set; }

        public static string DashboardLaunchUrl =>
            string.IsNullOrEmpty(SessionToken)
                ? DashboardUrl
                : DashboardUrl + "?token=" + Uri.EscapeDataString(SessionToken);

        private readonly QuarantineManager _quarantine;
        private readonly SentinelConfig _config;
        private readonly ILogger<WebDashboardService> _logger;
        private readonly SignerTrustService? _signerTrust;
        private readonly DllUnloadEngine? _dllUnload;
        private readonly ConcurrentBag<WebSocket> _wsClients = new();
        private readonly string _csrfToken;
        private readonly string _bearerToken;
        private HttpListener? _listener;

        private static readonly string ProgramDataRoot =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel");

        public WebDashboardService(
            QuarantineManager quarantine,
            SentinelConfig config,
            ILogger<WebDashboardService> logger,
            SignerTrustService? signerTrust = null,
            DllUnloadEngine? dllUnload = null)
        {
            _quarantine = quarantine;
            _config = config;
            _logger = logger;
            _signerTrust = signerTrust;
            _dllUnload = dllUnload;

            // Generate CSRF token for POST requests
            var bytes = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(bytes);
            _csrfToken = Convert.ToBase64String(bytes);

            // v2.1.7 RT-2026-M3: Generate bearer token for API authentication.
            // This closes the localhost-attacker vulnerability where any local process
            // could access the dashboard API without authentication.
            var bearerBytes = new byte[24];
            using (var rng2 = RandomNumberGenerator.Create())
                rng2.GetBytes(bearerBytes);
            _bearerToken = Convert.ToBase64String(bearerBytes);
            SessionToken = _bearerToken;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add(DashboardUrl);

            try
            {
                _listener.Start();
                _logger.LogInformation("[WebDashboard] Listening on {Url}", DashboardUrl);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WebDashboard] Failed to start HttpListener - dashboard disabled");
                return;
            }

            // Start the event log file watcher for WebSocket broadcast
            _ = Task.Run(() => WatchAndBroadcastEvents(stoppingToken), stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var context = await _listener.GetContextAsync().ConfigureAwait(false);
                    _ = Task.Run(() => HandleRequestAsync(context, stoppingToken), stoppingToken);
                }
                catch (HttpListenerException) when (stoppingToken.IsCancellationRequested)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[WebDashboard] Request error");
                }
            }
        }

        public override Task StopAsync(CancellationToken cancellationToken)
        {
            try { _listener?.Stop(); } catch { }
            try { _listener?.Close(); } catch { }
            return base.StopAsync(cancellationToken);
        }

        private async Task HandleRequestAsync(HttpListenerContext context, CancellationToken ct)
        {
            var request = context.Request;
            var response = context.Response;

            try
            {
                // v2.1.7 SECURITY: Reject non-localhost requests (defense-in-depth)
                if (!IsLocalRequest(request))
                {
                    response.StatusCode = 403;
                    response.Close();
                    return;
                }

                var path = request.Url?.AbsolutePath ?? "/";
                var method = request.HttpMethod;

                // WebSocket upgrade - v2.2.0: same bearer as /api (query ?token=).
                if (request.IsWebSocketRequest && path == "/ws/events")
                {
                    if (!ValidateBearerToken(request, response))
                        return;
                    try
                    {
                        await HandleWebSocket(context, ct).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "[WebDashboard] WebSocket upgrade failed");
                        response.StatusCode = 500;
                        response.Close();
                    }
                    return;
                }

                // WebSocket not supported - return 426 so client falls back to polling
                if (path == "/ws/events")
                {
                    response.StatusCode = 426;
                    response.Close();
                    return;
                }

                // CORS headers - localhost only (never wildcard; prevents cross-origin attacks from malicious sites)
                response.Headers.Add("Access-Control-Allow-Origin", "http://localhost:19845");
                response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization");
                response.Headers.Add("Vary", "Origin");

                if (method == "OPTIONS")
                {
                    response.StatusCode = 204;
                    response.Close();
                    return;
                }

                // Route
                if (path == "/" || path == "/index.html")
                {
                    await ServeHtml(response).ConfigureAwait(false);
                }
                else if (path == "/api/icon")
                {
                    await ServeIcon(response).ConfigureAwait(false);
                }
                else if (path.StartsWith("/api/"))
                {
                    // v2.2.0: Bearer (header or ?token=) is the only authenticator.
                    // Referer is ignored - it is client-controlled on HttpListener.
                    if (!ValidateBearerToken(request, response))
                        return;

                    await HandleApi(path, method, request, response, ct).ConfigureAwait(false);
                }
                else
                {
                    response.StatusCode = 404;
                    await WriteJson(response, new { error = "not_found" }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WebDashboard] Handler error");
                try
                {
                    response.StatusCode = 500;
                    response.Close();
                }
                catch { }
            }
        }

        private async Task HandleApi(string path, string method, HttpListenerRequest request, HttpListenerResponse response, CancellationToken ct)
        {
            response.ContentType = "application/json";

            switch (path)
            {
                case "/api/status":
                    await HandleStatus(response).ConfigureAwait(false);
                    break;
                case "/api/events":
                    await HandleEvents(response, request).ConfigureAwait(false);
                    break;
                case "/api/ops":
                    await HandleOps(response).ConfigureAwait(false);
                    break;
                case "/api/health":
                    await HandleHealth(response).ConfigureAwait(false);
                    break;
                case "/api/quarantine":
                    await HandleQuarantine(response).ConfigureAwait(false);
                    break;
                case "/api/packs":
                    await HandlePacks(response).ConfigureAwait(false);
                    break;
                case "/api/scan":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    if (!ValidateCsrf(request, response)) return;
                    await HandleScan(response).ConfigureAwait(false);
                    break;
                case "/api/scan/status":
                    await HandleScanStatus(response).ConfigureAwait(false);
                    break;
                case "/api/csrf":
                    // v2.2.0: CSRF is only issued to already-authenticated callers (bearer).
                    await WriteJson(response, new { token = _csrfToken }).ConfigureAwait(false);
                    break;
                case "/api/report/prefs":
                    await HandleReportPrefs(response).ConfigureAwait(false);
                    break;
                case "/api/report/save":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    if (!ValidateCsrf(request, response)) return;
                    await HandleReportSave(request, response).ConfigureAwait(false);
                    break;
                case "/api/report/verify":
                    await HandleReportVerify(response).ConfigureAwait(false);
                    break;
                case "/api/hardened":
                    await HandleHardenedStatus(response).ConfigureAwait(false);
                    break;
                case "/api/hardened/toggle":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    if (!ValidateCsrf(request, response)) return;
                    await HandleHardenedToggle(response).ConfigureAwait(false);
                    break;
                case "/api/diagnostics":
                    await HandleDiagnostics(response).ConfigureAwait(false);
                    break;
                case "/api/modules/processes":
                    await HandleModuleProcesses(response).ConfigureAwait(false);
                    break;
                case "/api/modules/audit":
                    await HandleModuleAudit(request, response).ConfigureAwait(false);
                    break;
                case "/api/modules/remediate":
                    if (method != "POST") { response.StatusCode = 405; response.Close(); return; }
                    if (!ValidateCsrf(request, response)) return;
                    await HandleModuleRemediate(request, response).ConfigureAwait(false);
                    break;
                default:
                    response.StatusCode = 404;
                    await WriteJson(response, new { error = "unknown_endpoint" }).ConfigureAwait(false);
                    break;
            }
        }

        #region API Handlers

        private async Task HandleModuleProcesses(HttpListenerResponse response)
        {
            try
            {
                var processes = ProcessModuleAuditor.GetActiveProcesses();
                await WriteJson(response, new { ok = true, processes }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WebDashboard] Failed to enumerate processes for module auditor");
                response.StatusCode = 500;
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleModuleAudit(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                var pidStr = request.QueryString["pid"];
                if (!int.TryParse(pidStr, out int pid) || pid <= 0)
                {
                    response.StatusCode = 400;
                    await WriteJson(response, new { ok = false, error = "valid_pid_required" }).ConfigureAwait(false);
                    return;
                }

                var audit = ProcessModuleAuditor.AuditProcess(pid, _signerTrust);
                await WriteJson(response, new { ok = true, audit }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WebDashboard] Module audit failed");
                response.StatusCode = 500;
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleModuleRemediate(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
                var json = await reader.ReadToEndAsync().ConfigureAwait(false);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                int pid = root.TryGetProperty("pid", out var pElem) && pElem.TryGetInt32(out int pVal) ? pVal : 0;
                string path = root.TryGetProperty("path", out var pathElem) ? (pathElem.GetString() ?? "") : "";

                if (string.IsNullOrEmpty(path))
                {
                    response.StatusCode = 400;
                    await WriteJson(response, new { ok = false, error = "missing_path" }).ConfigureAwait(false);
                    return;
                }

                bool remediated = false;
                string message;

                if (_dllUnload != null)
                {
                    var res = await _dllUnload.OnSideloadDllDroppedAsync(path, pid, $"Process_{pid}").ConfigureAwait(false);
                    remediated = res.Success;
                    message = remediated ? "Remediated via DllUnloadEngine" : "DllUnloadEngine completed without quarantine";
                }
                else
                {
                    var qPath = await _quarantine.QuarantineFileAtomicAsync(path, forceQuarantineSigned: true).ConfigureAwait(false);
                    remediated = !string.IsNullOrEmpty(qPath);
                    message = remediated ? $"Quarantined to {Path.GetFileName(qPath)}" : "Quarantine refused or failed";
                }

                await WriteJson(response, new
                {
                    ok = remediated,
                    path,
                    pid,
                    message
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[WebDashboard] Module remediation failed");
                response.StatusCode = 500;
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        /// <summary>
        /// v2.1.7 SECURITY: Validates CSRF token on state-changing (POST) requests.
        /// Returns false and writes a 403 response if validation fails.
        /// </summary>
        private bool ValidateCsrf(HttpListenerRequest request, HttpListenerResponse response)
        {
            var token = request.Headers["X-CSRF-Token"];
            if (string.IsNullOrEmpty(token) || !string.Equals(token, _csrfToken, StringComparison.Ordinal))
            {
                response.StatusCode = 403;
                response.ContentType = "application/json";
                var msg = Encoding.UTF8.GetBytes("{\"error\":\"csrf_validation_failed\"}");
                response.ContentLength64 = msg.Length;
                response.OutputStream.Write(msg, 0, msg.Length);
                response.Close();
                _logger.LogWarning("[WebDashboard] CSRF validation failed - possible cross-origin attack");
                return false;
            }
            return true;
        }

        /// <summary>
        /// v2.2.0: Bearer token authentication. Referer is never accepted as proof of origin.
        /// Token comes from Authorization: Bearer or ?token= (WebSocket / tray launch URL).
        /// </summary>
        private bool ValidateBearerToken(HttpListenerRequest request, HttpListenerResponse response)
        {
            var authHeader = request.Headers["Authorization"];
            var queryToken = request.QueryString["token"];

            if (LoopbackDashboardAuth.Authenticate(authHeader, queryToken, _bearerToken))
                return true;

            response.StatusCode = 401;
            response.ContentType = "application/json";
            var msg = Encoding.UTF8.GetBytes("{\"error\":\"unauthorized\",\"hint\":\"Bearer token required. Open the dashboard from the Sentinel tray icon.\"}");
            response.ContentLength64 = msg.Length;
            response.OutputStream.Write(msg, 0, msg.Length);
            response.Close();
            _logger.LogWarning("[WebDashboard] Bearer token auth failed - unauthorized API access attempt");
            return false;
        }

        /// <summary>
        /// v2.1.7 SECURITY: Validates that the request originates from localhost.
        /// Rejects requests from remote IPs (shouldn't happen with HttpListener on localhost,
        /// but defense-in-depth against misconfigured proxies).
        /// </summary>
        private static bool IsLocalRequest(HttpListenerRequest request)
        {
            var remote = request.RemoteEndPoint?.Address;
            if (remote == null) return false;
            return IPAddress.IsLoopback(remote);
        }

        /// <summary>Constant-time string comparison to prevent timing attacks on bearer token.</summary>
        private static bool ConstantTimeEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private async Task HandleStatus(HttpListenerResponse response)
        {
            bool serviceRunning = false;
            try
            {
                var procs = System.Diagnostics.Process.GetProcessesByName("Sentinel.Service");
                serviceRunning = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
            }
            catch { }

            var version = typeof(WebDashboardService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
            await WriteJson(response, new
            {
                ok = true,
                version,
                serviceRunning,
                protectionActive = serviceRunning,
                uptime = Environment.TickCount / 1000,
            }).ConfigureAwait(false);
        }

        private async Task HandleEvents(HttpListenerResponse response, HttpListenerRequest request)
        {
            int count = 50;
            var countParam = request.QueryString["count"];
            if (!string.IsNullOrEmpty(countParam) && int.TryParse(countParam, out int c))
                count = Math.Min(c, 500);

            var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");
            var events = new List<object>();

            if (File.Exists(logFile))
            {
                try
                {
                    var lines = ReadLastLines(logFile, count);
                    foreach (var line in lines)
                    {
                        try
                        {
                            using var doc = JsonDocument.Parse(line);
                            var root = doc.RootElement;
                            events.Add(new
                            {
                                type = root.TryGetProperty("type", out var t) ? t.GetString() : "unknown",
                                timestamp = root.TryGetProperty("timestamp", out var ts) ? ts.GetString() : "",
                                data = line, // raw JSON for frontend to parse
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }

            events.Reverse();
            await WriteJson(response, new { ok = true, events, total = events.Count }).ConfigureAwait(false);
        }

        private async Task HandleOps(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("ops", "", 3000);
            if (!string.IsNullOrEmpty(result))
            {
                response.ContentType = "application/json";
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                // Fallback: read ops_metrics.json
                var metricsFile = Path.Combine(ProgramDataRoot, "ops_metrics.json");
                if (File.Exists(metricsFile))
                {
                    try
                    {
                        var json = File.ReadAllText(metricsFile);
                        // Wrap in {ok, ops} envelope to match IPC response format
                        var wrapped = $"{{\"ok\":true,\"ops\":{json}}}";
                        response.ContentType = "application/json";
                        var buffer = Encoding.UTF8.GetBytes(wrapped);
                        response.ContentLength64 = buffer.Length;
                        await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                        response.Close();
                    }
                    catch
                    {
                        await WriteJson(response, new { ok = false, error = "metrics_unavailable" }).ConfigureAwait(false);
                    }
                }
                else
                {
                    await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
                }
            }
        }

        private async Task HandleHealth(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("health", "", 3000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleQuarantine(HttpListenerResponse response)
        {
            try
            {
                var raw = _quarantine.ListQuarantined();
                var items = raw.Select(t => new
                {
                    OriginalName = t.DisplayName,
                    OriginalPath = t.OriginalPath ?? "",
                    QuarantineFile = t.QuarantineFile,
                    QuarantinedAt = File.Exists(t.QuarantineFile)
                        ? File.GetCreationTimeUtc(t.QuarantineFile).ToString("o")
                        : ""
                }).ToList();
                await WriteJson(response, new { ok = true, items }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandlePacks(HttpListenerResponse response)
        {
            var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
            var packs = new List<object>();

            if (Directory.Exists(packsDir))
            {
                try
                {
                    foreach (var dir in Directory.GetDirectories(packsDir, "AUTO_*"))
                    {
                        var dirInfo = new DirectoryInfo(dir);
                        var manifestFile = Path.Combine(dir, "manifest.sha256");
                        bool hasManifest = File.Exists(manifestFile);
                        packs.Add(new
                        {
                            name = dirInfo.Name,
                            path = dir,
                            created = dirInfo.CreationTimeUtc,
                            hasManifest,
                            fileCount = Directory.GetFiles(dir).Length
                        });
                    }
                }
                catch { }
            }

            await WriteJson(response, new { ok = true, packs }).ConfigureAwait(false);
        }

        private async Task HandleScan(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("scan", "", 5000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleScanStatus(HttpListenerResponse response)
        {
            var result = ServiceAgentIpcClient.Request("scan_status", "", 5000);
            if (!string.IsNullOrEmpty(result))
            {
                var buffer = Encoding.UTF8.GetBytes(result);
                response.ContentLength64 = buffer.Length;
                await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
                response.Close();
            }
            else
            {
                await WriteJson(response, new { ok = false, error = "service_unreachable" }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportPrefs(HttpListenerResponse response)
        {
            try
            {
                var prefs = UserReportPrefs.Load();
                await WriteJson(response, new { ok = true, prefs }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportSave(HttpListenerRequest request, HttpListenerResponse response)
        {
            try
            {
                using var reader = new StreamReader(request.InputStream, request.ContentEncoding);
                var body = await reader.ReadToEndAsync().ConfigureAwait(false);
                var prefs = JsonSerializer.Deserialize<UserReportPrefs>(body, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (prefs != null)
                {
                    prefs.Save();
                    await WriteJson(response, new { ok = true }).ConfigureAwait(false);
                }
                else
                {
                    await WriteJson(response, new { ok = false, error = "invalid_body" }).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleReportVerify(HttpListenerResponse response)
        {
            try
            {
                var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
                if (!Directory.Exists(packsDir))
                {
                    await WriteJson(response, new { ok = true, message = "No evidence packs to verify" }).ConfigureAwait(false);
                    return;
                }

                int verified = 0, failed = 0;
                foreach (var dir in Directory.GetDirectories(packsDir, "AUTO_*"))
                {
                    var manifest = Path.Combine(dir, "manifest.sha256");
                    if (File.Exists(manifest))
                        verified++;
                    else
                        failed++;
                }

                var msg = failed == 0
                    ? $"All {verified} pack(s) have integrity manifests"
                    : $"{verified} verified, {failed} missing manifest";

                await WriteJson(response, new { ok = true, message = msg, verified, failed }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        private async Task HandleHardenedStatus(HttpListenerResponse response)
        {
            // v2.5.5: Hardening is always-on.
            await WriteJson(response, new { ok = true, enabled = true, alwaysOn = true }).ConfigureAwait(false);
        }

        private async Task HandleHardenedToggle(HttpListenerResponse response)
        {
            // v2.5.5: Hardening is always-on and cannot be disabled.
            response.StatusCode = 400;
            await WriteJson(response, new
            {
                ok = false,
                error = "Hardening is always-on as of v2.5.5 and cannot be disabled.",
                enabled = true,
                alwaysOn = true
            }).ConfigureAwait(false);
        }

        private async Task HandleDiagnostics(HttpListenerResponse response)
        {
            try
            {
                var sb = new System.Text.StringBuilder();
                var version = typeof(WebDashboardService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
                sb.AppendLine($"Sentinel diagnostics - {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
                sb.AppendLine($"Agent version: {version}");

                bool agentRunning = false, serviceRunning = false;
                try
                {
                    agentRunning = System.Diagnostics.Process.GetProcessesByName("Sentinel.Agent").Length > 0;
                    serviceRunning = System.Diagnostics.Process.GetProcessesByName("Sentinel.Service").Length > 0;
                }
                catch { }

                sb.AppendLine($"Agent process: {(agentRunning ? "running" : "not found")}");
                sb.AppendLine($"Service process: {(serviceRunning ? "running" : "not found")}");
                sb.AppendLine($"Machine: {Environment.MachineName}");
                sb.AppendLine($"User: {Environment.UserDomainName}\\{Environment.UserName}");
                sb.AppendLine($"OS: {Environment.OSVersion}");
                sb.AppendLine($"Hardened Mode: ENABLED (always-on)");                sb.AppendLine();
                sb.AppendLine("Paths:");
                sb.AppendLine($"  Install:     {AppContext.BaseDirectory}");
                sb.AppendLine($"  ProgramData: {ProgramDataRoot}");

                var eventsPath = Path.Combine(ProgramDataRoot, "events.jsonl");
                var eventsSize = File.Exists(eventsPath) ? new FileInfo(eventsPath).Length : 0;
                sb.AppendLine($"  Events:      {eventsPath}  ({eventsSize / 1024} KB)");
                sb.AppendLine($"  Quarantine:  {Path.Combine(ProgramDataRoot, "Quarantine")}");

                var packsDir = Path.Combine(ProgramDataRoot, "IncidentReports");
                var packCount = Directory.Exists(packsDir) ? Directory.GetDirectories(packsDir, "AUTO_*").Length : 0;
                sb.AppendLine($"  Evidence:    {packsDir}  ({packCount} packs)");
                sb.AppendLine();
                sb.AppendLine("IPC status:");
                var pingResult = ServiceAgentIpcClient.Request("ping", "", 2000);
                sb.AppendLine($"  Ping: {(string.IsNullOrEmpty(pingResult) ? "FAILED (service unreachable)" : "OK")}");

                await WriteJson(response, new { ok = true, text = sb.ToString() }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                await WriteJson(response, new { ok = false, error = ex.Message }).ConfigureAwait(false);
            }
        }

        #endregion

        #region WebSocket

        private async Task HandleWebSocket(HttpListenerContext context, CancellationToken ct)
        {
            WebSocketContext wsContext;
            try
            {
                wsContext = await context.AcceptWebSocketAsync(null).ConfigureAwait(false);
            }
            catch
            {
                context.Response.StatusCode = 500;
                context.Response.Close();
                return;
            }

            var ws = wsContext.WebSocket;
            _wsClients.Add(ws);

            try
            {
                var buffer = new byte[1024];
                while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var result = await ws.ReceiveAsync(new ArraySegment<byte>(buffer), ct).ConfigureAwait(false);
                    if (result.MessageType == WebSocketMessageType.Close)
                        break;
                    // We don't process incoming messages - this is a push-only stream
                }
            }
            catch { }
            finally
            {
                try { ws.Dispose(); } catch { }
            }
        }

        private async Task BroadcastEvent(string json)
        {
            var deadSockets = new List<WebSocket>();
            foreach (var ws in _wsClients)
            {
                if (ws.State != WebSocketState.Open)
                {
                    deadSockets.Add(ws);
                    continue;
                }
                try
                {
                    var buffer = Encoding.UTF8.GetBytes(json);
                    await ws.SendAsync(new ArraySegment<byte>(buffer), WebSocketMessageType.Text, true, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                catch
                {
                    deadSockets.Add(ws);
                }
            }

            // Clean up dead sockets (ConcurrentBag doesn't support remove, rebuild if needed)
            // This is fine for a small number of clients (typically 1-3 browser tabs)
        }

        private async Task WatchAndBroadcastEvents(CancellationToken ct)
        {
            var logFile = Path.Combine(ProgramDataRoot, "events.jsonl");

            // Wait for file to exist
            while (!File.Exists(logFile) && !ct.IsCancellationRequested)
                await Task.Delay(2000, ct).ConfigureAwait(false);

            long lastOffset = 0;
            try
            {
                if (File.Exists(logFile))
                {
                    using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete);
                    lastOffset = fs.Length;
                }
            }
            catch { }

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (File.Exists(logFile))
                    {
                        using var fs = new FileStream(logFile, FileMode.Open, FileAccess.Read,
                            FileShare.ReadWrite | FileShare.Delete);

                        if (fs.Length < lastOffset)
                            lastOffset = 0;

                        if (fs.Length > lastOffset)
                        {
                            fs.Seek(lastOffset, SeekOrigin.Begin);
                            using var reader = new StreamReader(fs, Encoding.UTF8, false, 4096, true);
                            string? line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (!string.IsNullOrWhiteSpace(line))
                                    await BroadcastEvent(line).ConfigureAwait(false);
                            }
                            lastOffset = fs.Position;
                        }
                    }
                }
                catch { }

                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
        }

        #endregion

        #region Helpers

        private static async Task WriteJson(HttpListenerResponse response, object data)
        {
            response.ContentType = "application/json";
            var json = JsonSerializer.Serialize(data);
            var buffer = Encoding.UTF8.GetBytes(json);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            response.Close();
        }

        private async Task ServeHtml(HttpListenerResponse response)
        {
            response.ContentType = "text/html; charset=utf-8";
            response.Headers.Add("X-Content-Type-Options", "nosniff");
            response.Headers.Add("X-Frame-Options", "DENY");
            response.Headers.Add("Cache-Control", "no-store");
            var html = DashboardHtml.GetHtml(_bearerToken);
            var buffer = Encoding.UTF8.GetBytes(html);
            response.ContentLength64 = buffer.Length;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length).ConfigureAwait(false);
            response.Close();
        }

        private async Task ServeIcon(HttpListenerResponse response)
        {
            try
            {
                var icoPath = Path.Combine(AppContext.BaseDirectory, "Sentinel.ico");
                if (File.Exists(icoPath))
                {
                    response.ContentType = "image/x-icon";
                    var bytes = File.ReadAllBytes(icoPath);
                    response.ContentLength64 = bytes.Length;
                    await response.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
                    response.Close();
                }
                else
                {
                    response.StatusCode = 404;
                    response.Close();
                }
            }
            catch
            {
                response.StatusCode = 500;
                response.Close();
            }
        }

        private static List<string> ReadLastLines(string filePath, int lineCount)
        {
            var lines = new List<string>();
            try
            {
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(fs, Encoding.UTF8);

                // Read all lines and take last N (simple approach for JSONL files < 50MB)
                string? line;
                var buffer = new Queue<string>(lineCount + 1);
                while ((line = reader.ReadLine()) != null)
                {
                    buffer.Enqueue(line);
                    if (buffer.Count > lineCount)
                        buffer.Dequeue();
                }
                lines.AddRange(buffer);
            }
            catch { }
            return lines;
        }

        #endregion
    }
}
