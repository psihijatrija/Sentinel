using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Sentinel.Core;

namespace Sentinel.Agent
{
    public class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeConsole();

        //  Self-restart state 
        // v2.0.3: File-based restart counter (replaces env var which leaked into
        // child processes and could be polluted by inheritance). The marker file
        // stores a timestamp + count; stale markers (>60s old) are treated as fresh.
        private const int MaxSelfRestarts = 5;
        private const int RestartWindowSeconds = 60;
        // 

        //  Single-instance guard 
        // Multiple launch paths can race (installer, Run key, AgentWatchdog,
        // self-restart). A named mutex prevents duplicate tray icons.
        private const string SingleInstanceMutexName = "Global\\SentinelAgentSingleInstance";
        // 

        [STAThread]
        public static void Main(string[] args)
        {
            //  Single-instance check (before anything else) 
            using var instanceMutex = new Mutex(true, SingleInstanceMutexName, out bool createdNew);
            if (!createdNew)
            {
                // Another Agent instance is already running - exit silently.
                return;
            }

            //  Crash handlers (registered first, before any allocations) 
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                LogCrash("UnhandledException", e.ExceptionObject as Exception);
                // v1.3.9: On terminal crash, schedule a self-relaunch before we exit.
                // This covers exception types that kill the process before the finally
                // block in Run() can fire (e.g., StackOverflowException-adjacent CLR faults).
                if (e.IsTerminating)
                    ScheduleDelayedRelaunch(args);
            };

            System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
            {
                LogCrash("UnobservedTaskException", e.Exception);
                e.SetObserved();
            };

            System.Windows.Forms.Application.ThreadException += (s, e) =>
            {
                LogCrash("ThreadException", e.Exception);
            };

            //  Hardening 
            HardeningModule.ApplyOrFail();

            // Detach from parent console window (installer / Run key launch)
            try { FreeConsole(); } catch { }

            //  Build & run host 
            var host = CreateHostBuilder(args).Build();

            // v1.3.9: Wire the orchestrator into the detection engine so
            // agent-side detections flow through incident grouping and response
            // coordination instead of falling back to the bare response engine.
            var detectionEngine = host.Services.GetRequiredService<DetectionEngine>();
            var orchestrator    = host.Services.GetRequiredService<SentinelOrchestrator>();
            detectionEngine.SetOrchestrator(orchestrator);

            // v2.6.0: Wire ancestry cache into ResponsePolicy for cross-PID chain correlation.
            ResponsePolicy.SetAncestryCache(host.Services.GetRequiredService<ProcessAncestryCache>());

            // v2.0.3: Clear restart marker on successful startup - host built and wired
            ClearRestartMarker();

            try
            {
                host.Run();
            }
            catch (Exception ex)
            {
                // Host-level crash (e.g., a BackgroundService threw out of ExecuteAsync
                // in a way the generic host didn't swallow)
                LogCrash("HostCrash", ex);
            }
            finally
            {
                // v1.3.9: Self-restart on exit - covers all normal and abnormal exits
                // except the IsTerminating path above (which calls ScheduleDelayedRelaunch).
                // The AgentWatchdog in the Service is the authoritative restarter; this is
                // a belt-and-suspenders fallback for the window before the watchdog notices.
                TryImmediateRestart(args);
            }
        }

        // 
        // Self-restart helpers
        // 

        /// <summary>
        /// Attempts to re-launch this process immediately.
        /// Called from the finally block after the host exits.
        ///
        /// Guards:
        ///   - Only restarts on unclean exit (non-zero expected lifecycle exits are
        ///     not currently signalled, so we restart on every exit - the watchdog
        ///     dedup window prevents storms).
        ///   - v2.0.3: File-based restart counter prevents crash-loop amplification
        ///     beyond MaxSelfRestarts within a rolling window.
        /// </summary>
        private static void TryImmediateRestart(string[] args)
        {
            try
            {
                int restartCount = ReadAndIncrementRestartMarker();

                if (restartCount >= MaxSelfRestarts)
                {
                    // Too many rapid self-restarts - let the AgentWatchdog (Service side) handle it
                    LogCrash("SelfRestartAborted",
                        new InvalidOperationException(
                            $"Self-restart limit ({MaxSelfRestarts}) reached within {RestartWindowSeconds}s. " +
                            "Waiting for AgentWatchdog to recover the agent."));
                    return;
                }

                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return;

                // Brief cooldown to avoid tight restart loops on repeated immediate crashes
                Thread.Sleep(2000);

                var psi = new ProcessStartInfo(exePath)
                {
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                if (args != null && args.Length > 0)
                    psi.Arguments = string.Join(" ", args);

                Process.Start(psi);
            }
            catch
            {
                // Best-effort - if we can't self-restart, the AgentWatchdog will cover it
            }
        }

        /// <summary>
        /// Called from the UnhandledException handler when IsTerminating=true.
        /// The process is about to die before the finally block can run, so we
        /// spawn a new instance directly.
        /// v2.0.3: Uses file-based restart counter (no env var inheritance).
        /// </summary>
        private static void ScheduleDelayedRelaunch(string[] args)
        {
            try
            {
                int restartCount = ReadAndIncrementRestartMarker();
                if (restartCount >= MaxSelfRestarts) return;

                var exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
                    return;

                var psi = new ProcessStartInfo(exePath)
                {
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                if (args != null && args.Length > 0)
                    psi.Arguments = string.Join(" ", args);

                Process.Start(psi);
            }
            catch { }
        }

        // 
        // File-based restart marker (v2.0.3)
        // 

        /// <summary>
        /// Reads the current restart count from the marker file. If the marker is
        /// stale (older than RestartWindowSeconds), resets to 0. Increments and writes back.
        /// Returns the count BEFORE increment (i.e., how many restarts have already occurred).
        /// </summary>
        private static int ReadAndIncrementRestartMarker()
        {
            try
            {
                var markerPath = GetRestartMarkerPath();
                int count = 0;

                if (File.Exists(markerPath))
                {
                    var content = File.ReadAllText(markerPath).Trim();
                    var parts = content.Split('|');
                    if (parts.Length == 2 &&
                        long.TryParse(parts[0], out long ticks) &&
                        int.TryParse(parts[1], out int existingCount))
                    {
                        var markerTime = new DateTime(ticks, DateTimeKind.Utc);
                        if ((DateTime.UtcNow - markerTime).TotalSeconds <= RestartWindowSeconds)
                        {
                            count = existingCount;
                        }
                        // else: stale marker - treat as fresh (count stays 0)
                    }
                }

                // Write incremented marker
                var newContent = $"{DateTime.UtcNow.Ticks}|{count + 1}";
                File.WriteAllText(markerPath, newContent);

                return count;
            }
            catch
            {
                // If we can't read/write the marker, allow restart (fail-open)
                return 0;
            }
        }

        /// <summary>
        /// Clears the restart marker on successful startup (host fully built and running).
        /// Called after the host starts successfully.
        /// </summary>
        private static void ClearRestartMarker()
        {
            try
            {
                var markerPath = GetRestartMarkerPath();
                if (File.Exists(markerPath))
                    File.Delete(markerPath);
            }
            catch { }
        }

        private static string GetRestartMarkerPath()
        {
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(programData, "Sentinel", ".agent_restart_marker");
        }

        // 
        // Crash logger
        // 

        private static void LogCrash(string type, Exception? ex)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var crashLog = Path.Combine(programData, "Sentinel", "agent_crash.log");
                var msg = $"[{DateTime.UtcNow:o}] [{type}] {ex?.Message}\n{ex?.StackTrace}" +
                          $"\nInnerException: {ex?.InnerException?.Message}\n{ex?.InnerException?.StackTrace}" +
                          $"\n-----------------------------------\n";
                File.AppendAllText(crashLog, msg);
            }
            catch { }
        }

        // 
        // Host builder
        // 

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((_, cfg) => HostDiskJson.RemoveJsonSources(cfg))
                .ConfigureServices((hostContext, services) =>
                {
                    var config = new SentinelConfig();
                    var threatReportingConfig = new ThreatReportingConfig();
                    var autoIncidentReportingConfig = new AutoIncidentReportingConfig();
                    var store = new EncryptedConfigStore();
                    store.ApplyOverrides(config, threatReportingConfig, autoIncidentReportingConfig);
                    // v2.9.4: ObserveUntilChain is hardwired false (no-op setter in Models.cs);
                    // the former `config.ObserveUntilChain = true` line is removed - observe mode
                    // can no longer be selected by config, override, or planted file.
                    if (!ProxyAuthHelper.HasSharedSecret(threatReportingConfig))
                        threatReportingConfig.ProxySharedSecret = ThreatReportingConfig.CompiledProxySharedSecret;
                    services.AddSingleton(config);
                    services.AddSingleton(threatReportingConfig);
                    services.AddSingleton(autoIncidentReportingConfig);

                    // Infrastructure required by monitors
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<ThreatReportService>();
                    services.AddSingleton<ToastService>();
                    services.AddSingleton<AutoIncidentReporter>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    services.AddSingleton<SafeProcessExemptionRegistry>();
                    services.AddSingleton<FileVerdictAds>();
                    services.AddSingleton<IoCScanner>();
                    services.AddSingleton<AllowlistService>();
                    services.AddSingleton<SignerTrustService>();
                    services.AddSingleton<ScoringEngine>();
                    services.AddSingleton<ChainTracer>();
                    services.AddSingleton<DllUnloadEngine>();
                    services.AddSingleton<FileReputationEngine>();
                    services.AddSingleton<DetectionEngine>();

                    // v1.3.2: Orchestration layer
                    services.AddSingleton<IncidentManager>();
                    services.AddSingleton<MonitorRegistry>();
                    services.AddSingleton<StartupSequencer>();
                    services.AddSingleton<ContextBus>();
                    services.AddSingleton<ResponseCoordinator>();
                    services.AddSingleton<SentinelOrchestrator>();
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();
                    services.AddTransient<IDetectionRule, IdsCommandLineRule>();
                    services.AddTransient<IDetectionRule, VerdictGateRule>();
                    services.AddTransient<IDetectionRule, ClickFixDetectionRule>();
                    services.AddTransient<IDetectionRule, NpmSupplyChainRule>();
                    services.AddTransient<IDetectionRule, DllSideloadingDetectionRule>();
                    services.AddTransient<IDetectionRule, ChromeRemoteDebuggingRule>();
                    services.AddTransient<IDetectionRule, DangerousBrowserFlagRule>();
                    services.AddSingleton<IDetectionRule, DynamicRulesEvaluator>();
                    // GorstaksProtection-ported rules (v2.4.0)
                    services.AddSingleton<IDetectionRule, SlidingWindowRansomwareRule>();
                    services.AddSingleton<IDetectionRule, SlidingWindowMassDeletionRule>();
                    services.AddSingleton<IDetectionRule, FullPathParentChildRule>();

                    // Web dashboard served on localhost + native WinForms shell.
                    // The embedded WebBrowser control in AgentDashboardForm connects to
                    // this service, avoiding the broken http protocol handler problem.
                    services.AddHostedService<WebDashboardService>();
                    services.AddHostedService<TrayIconService>();

                    // User-session monitors (require user desktop/registry hive)
                    services.AddHostedService<ScreenCaptureMonitor>();
                    services.AddHostedService<WebcamMicMonitor>();
                    services.AddHostedService<AudioHijackMonitor>();
                    services.AddHostedService<MicSessionMonitor>();
                    services.AddHostedService<NeuroBehaviorVisualMonitor>();
                    services.AddHostedService<BrowserExtensionMonitor>();
                    services.AddHostedService<PhantomKeystrokeGuard>();
                    services.AddHostedService<ClickjackingGuard>();
                    services.AddHostedService<WebcamHijackMonitor>();
                    services.AddHostedService<ShellWatchdog>();
                    // Ported from PowerShell Detection/ + Grok.ps1 (user-session UI monitors)
                    services.AddHostedService<ScarewareWindowMonitor>();
                    services.AddHostedService<CursorTakeoverMonitor>();
                    services.AddHostedService<CookieIntegrityMonitor>();
                    services.AddSingleton<IsolationResponseEngine>();
                });
    }
}
