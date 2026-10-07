using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.ServiceProcess;
using Sentinel.Core;            // all monitor classes (folder Monitors/ is layout only)
using Sentinel.Core.Plugins;
using Sentinel.Core.Monitors;
namespace Sentinel.Service
{
    /// <summary>
    /// Builds monitor-group member lists resiliently. On a heavily stripped-down Windows a
    /// monitor's constructor can throw (missing WMI/System.Management, absent registry hive,
    /// perf counters, a service, etc.). Resolving each member behind an isolated try/catch means
    /// one un-constructable monitor is skipped with a warning instead of faulting host startup
    /// and taking the whole group - and the process - down with it.
    /// </summary>
    internal static class SafeMonitorResolver
    {
        public static System.Collections.Generic.List<IHostedService> Build(
            IServiceProvider sp,
            params (string Name, Func<IServiceProvider, IHostedService> Factory)[] members)
        {
            var logger = sp.GetService<ILogger<Program>>();
            var list = new System.Collections.Generic.List<IHostedService>(members.Length);
            foreach (var (name, factory) in members)
            {
                try
                {
                    var m = factory(sp);
                    if (m != null) list.Add(m);
                }
                catch (Exception ex)
                {
                    logger?.LogWarning(
                        "[Startup] Monitor '{Monitor}' could not be constructed on this system and will be skipped (likely a missing OS facility on a stripped-down image): {Error}",
                        name, ex.Message);
                }
            }
            return list;
        }
    }

    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Isolated hard-fault attribution - no host, no monitors, no response actions.
            if (args.Length >= 1 && args[0].Equals("--pagefault-diag", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = PageFaultDiag.Run(args);
                return;
            }
            // Sample HardFaultCount of a live PID (LatencyMon-equivalent). Does not start Sentinel.
            if (args.Length >= 2 && args[0].Equals("--pagefault-watch", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = PageFaultDiag.Watch(args);
                return;
            }

            // v2.0.4: Handle --set-config before anything else (CLI config management)
            if (args.Length >= 2 && args[0].Equals("--set-config", StringComparison.OrdinalIgnoreCase))
            {
                HandleSetConfig(args);
                return;
            }

            // v2.3.9: Installer delegates SCM/Run-key work here so Inno Setup stays file-copy-only
            // (avoids embedding sc create / Run / taskkill / icacls heuristics in the setup EXE).
            if (args.Length >= 1 && args[0].Equals("--watchdog", StringComparison.OrdinalIgnoreCase))
            {
                if (Environment.UserInteractive)
                {
                    while (true)
                    {
                        try { InstallBootstrap.TryStartService(); } catch { }
                        Thread.Sleep(20000);
                    }
                }
                ServiceBase.Run(new SentinelGuardService());
                return;
            }
            if (args.Length >= 1 && args[0].Equals("--ensure-running", StringComparison.OrdinalIgnoreCase))
            {
                InstallBootstrap.TryStartService();
                return;
            }
            if (args.Length >= 1 && args[0].Equals("--install", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = InstallBootstrap.RunInstall();
                return;
            }
            if (args.Length >= 1 && args[0].Equals("--prepare-upgrade", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = InstallBootstrap.RunPrepareUpgrade();
                return;
            }
            if (args.Length >= 1 && args[0].Equals("--uninstall-cleanup", StringComparison.OrdinalIgnoreCase))
            {
                Environment.ExitCode = InstallBootstrap.RunUninstallCleanup();
                return;
            }

            // DIAGNOSTIC: Write immediately on process start, before anything else.
            // v1.8.1 RT-MED-3: ensure ProgramData\Sentinel exists with restricted ACLs
            // before any world-readable inherited default can apply to diagnostic files.
            AppendDiagnostic("startup_trace.log",
                $"[{DateTime.UtcNow:O}] Main() entered. Args: {string.Join(" ", args)}\n");

            // v2.5.5: Hardening is always-on - no early config read needed.
            // Self-protect Sentinel process and apply full lockdown immediately.
            HardeningModule.ApplyOrFail();

            // Secure Sentinel's installation directory permissions
            HardeningModule.SecureInstallationDirectory();

            var host = CreateHostBuilder(args).Build();

            // Wire up ReinfectionCorrelator -> AdvancedResponseEngine (avoids circular DI)
            var responseEngine = host.Services.GetService<AdvancedResponseEngine>();
            var correlator = host.Services.GetService<ReinfectionCorrelator>();
            if (responseEngine != null && correlator != null)
                responseEngine.SetReinfectionCorrelator(correlator);

            // DIAGNOSTIC v1.4.8: Log unhandled exceptions that kill the host.
            // The service was dying after ~16 seconds with no crash trace - this
            // catches whatever unobserved Task exception is triggering host shutdown.
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                var ex = e.ExceptionObject as Exception;
                var msg = $"[FATAL] UnhandledException in AppDomain: {ex?.GetType().Name}: {ex?.Message}\n{ex?.StackTrace}";
                AppendDiagnostic("fatal_crash.log", $"[{DateTime.UtcNow:O}] {msg}\n\n");
            };

            TaskScheduler.UnobservedTaskException += (_, e) =>
            {
                var msg = $"[UNOBSERVED] {e.Exception?.GetType().Name}: {e.Exception?.InnerException?.Message ?? e.Exception?.Message}\n{e.Exception?.InnerException?.StackTrace ?? e.Exception?.StackTrace}";
                AppendDiagnostic("fatal_crash.log", $"[{DateTime.UtcNow:O}] {msg}\n\n");
                e.SetObserved(); // Prevent process crash from unobserved tasks
            };

            // STABILITY v1.4.9: Use host.StartAsync() + manual infinite wait instead of host.Run().
            // host.Run() returns when ANY hosted service task completes, killing the process.
            // We start the host and then block Main forever - only SCM stop signal exits.
            AppendDiagnostic("startup_trace.log",
                $"[{DateTime.UtcNow:O}] Calling host.StartAsync()...\n");

            await host.StartAsync();

            // B1: mark a graceful host/OS stop as expected so the AntiTamperGuard exit hook does
            // not flag it as a suspicious tamper stop. Under UseWindowsService this fires on a
            // cooperative SCM stop and on SERVICE_CONTROL_SHUTDOWN (OS shutdown). A hard kill
            // never fires it, so a TerminateProcess still classifies as unexpected.
            try
            {
                var lifetime = host.Services.GetService<Microsoft.Extensions.Hosting.IHostApplicationLifetime>();
                lifetime?.ApplicationStopping.Register(() =>
                    Sentinel.Core.ShutdownContext.MarkExpected(
                        Sentinel.Core.ExpectedShutdownReason.SystemShutdown));
            }
            catch { /* best-effort lifecycle hook */ }

            AppendDiagnostic("startup_trace.log",
                $"[{DateTime.UtcNow:O}] host.StartAsync() completed. Blocking Main forever (ManualResetEvent)...\n");

            // Block Main() forever. NOTHING can make this return except process termination.
            // This prevents the .NET Host's "BackgroundService completed -> shutdown" behavior
            // from propagating to a process exit.
            Thread.Sleep(Timeout.Infinite);
        }

        /// <summary>
        /// CLI: Sentinel.Service.exe --set-config Key=Value
        /// Example: --set-config RestrictivePortHardening=true
        /// Cannot disable detection or rewrite compiled threat-proxy HMAC.
        /// </summary>
        private static void HandleSetConfig(string[] args)
        {
            var store = new EncryptedConfigStore();
            int count = 0;
            for (int i = 1; i < args.Length; i++)
            {
                var eqIdx = args[i].IndexOf('=');
                if (eqIdx <= 0)
                {
                    Console.Error.WriteLine($"Invalid format: '{args[i]}' - expected Key=Value");
                    continue;
                }
                var key = args[i].Substring(0, eqIdx).Trim();
                var value = args[i].Substring(eqIdx + 1);
                if (string.IsNullOrEmpty(value) || value.Equals("null", StringComparison.OrdinalIgnoreCase))
                {
                    store.SetOverride(key, null);
                    Console.WriteLine($"  Removed: {key}");
                }
                else
                {
                    store.SetOverride(key, value);
                    Console.WriteLine($"  Set: {key} = ****");
                }
                count++;
            }

            if (count > 0 && store.Save())
            {
                Console.WriteLine($"Saved {count} config value(s) to encrypted store.");
                Console.WriteLine("Restart the Sentinel service for changes to take effect.");
            }
            else if (count > 0)
            {
                Console.Error.WriteLine("ERROR: Failed to save encrypted config. Run as Administrator/SYSTEM.");
                Environment.ExitCode = 1;
            }
        }

        /// <summary>
        /// v1.8.1 RT-MED-3: Create %ProgramData%\Sentinel with SYSTEM+Admins-only ACL
        /// before writing early diagnostic files (prevents world-readable startup traces).
        /// </summary>
        private static void AppendDiagnostic(string fileName, string content)
        {
            try
            {
                var dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Sentinel");
                EnsureRestrictedProgramDataDir(dir);
                File.AppendAllText(Path.Combine(dir, fileName), content);
            }
            catch { }
        }

        private static void EnsureRestrictedProgramDataDir(string dirPath)
        {
            if (!Directory.Exists(dirPath))
                Directory.CreateDirectory(dirPath);

            try
            {
                var dirInfo = new DirectoryInfo(dirPath);
                var security = dirInfo.GetAccessControl();
                security.SetAccessRuleProtection(true, false);

                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    systemSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                var adminsSid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    adminsSid,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                // Interactive users must be able to open Data Folder / logs from the tray.
                // UAC-filtered Admin tokens are not BUILTIN\Administrators.
                var interactiveSid = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    interactiveSid,
                    FileSystemRights.ReadAndExecute,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                dirInfo.SetAccessControl(security);
            }
            catch { }
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseWindowsService()
                .ConfigureAppConfiguration((_, cfg) => HostDiskJson.RemoveJsonSources(cfg))
                .ConfigureServices((hostContext, services) =>
                {
                    // STABILITY v1.4.8: Prevent host shutdown when a BackgroundService
                    // completes or throws. Without this, if ANY MonitorGroup's ExecuteAsync
                    // returns (e.g., monitor startup failure), the entire host shuts down.
                    services.Configure<HostOptions>(opts =>
                    {
                        opts.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore;
                        opts.ServicesStartConcurrently = false;
                        opts.ServicesStopConcurrently = true;
                        opts.ShutdownTimeout = TimeSpan.FromSeconds(10);
                    });

                    // Compiled defaults + DPAPI config.enc only. Disk JSON is not bound.
                    var config = new SentinelConfig();
                    var threatReportingConfig = new ThreatReportingConfig();
                    var autoIncidentReportingConfig = new AutoIncidentReportingConfig();
                    var appIntegrityConfig = new ApplicationIntegrityConfig();
                    services.AddSingleton(autoIncidentReportingConfig);
                    services.AddSingleton(appIntegrityConfig);

                    var encryptedStore = new EncryptedConfigStore();
                    encryptedStore.ApplyOverrides(config, threatReportingConfig, autoIncidentReportingConfig);
                    // v2.9.4: ObserveUntilChain is hardwired false (no-op setter in Models.cs);
                    // the former `config.ObserveUntilChain = true` line is removed - observe mode
                    // can no longer be selected by config, override, or planted file.
                    if (!ProxyAuthHelper.HasSharedSecret(threatReportingConfig))
                        threatReportingConfig.ProxySharedSecret = ThreatReportingConfig.CompiledProxySharedSecret;
                    // v2.5.5: HardeningModule.RestrictivePortHardeningEnabled is always-on - no sync needed.
                    services.AddSingleton(encryptedStore);

                    // CLI flag overrides
                    for (int i = 0; i < args.Length; i++)
                    {
                        if ((args[i].Equals("--log", StringComparison.OrdinalIgnoreCase) || args[i].Equals("-l", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                        {
                            config.LogPath = args[++i];
                        }
                        else if ((args[i].Equals("--watch", StringComparison.OrdinalIgnoreCase) || args[i].Equals("-w", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                        {
                            config.WatchPath = args[++i];
                        }
                    }
                    services.AddSingleton(config);
                    services.AddSingleton(threatReportingConfig);
                    // Nested config (also bound via Sentinel.WindowsEventLog); expose as singleton for DI
                    var winEventLogCfg = config.WindowsEventLog ?? new WindowsEventLogConfig();
                    services.AddSingleton(winEventLogCfg);

                    // Infrastructure & Utilities
                    services.AddSingleton<SentinelMetrics>();
                    services.AddSingleton<ThreatReportService>();
                    // v1.9.5: Windows Event Log trail - self-disables on barebone/stripped images
                    services.AddSingleton<SentinelEventLogWriter>();
                    services.AddSingleton<AutoIncidentReporter>();
                    services.AddSingleton<JsonlEventLogger>(_ => new JsonlEventLogger(config.LogPath));
                    services.AddSingleton<EventGraph>();
                    services.AddSingleton<ProcessAncestryCache>();
                    services.AddSingleton<SecureCacheStore>();
                    services.AddSingleton<HashReputationService>();
                    services.AddSingleton<QuarantineManager>();
                    services.AddSingleton<SafeProcessExemptionRegistry>();
                    services.AddSingleton<FileVerdictAds>();
                    // v2.9.2: cheap path+size+mtime "already scanned" index. Lets FileVerdictScanner's
                    // drive walk skip unchanged files without re-reading + re-hashing them (the fix for
                    // sustained 18-50 MB/s HDD churn). Advisory, fail-open, not security-critical.
                    services.AddSingleton<FileScanIndex>(_ => new FileScanIndex());
                    // Utility services (SYSTEM-session safe only)
                    services.AddSingleton<UsbDeviceFingerprinter>();
                    services.AddSingleton<IoCScanner>();
                    services.AddSingleton<ParentPidSpoofDetector>();
                    // 1.8.4 ToastService: CriticalOnly (default true) - no SuppressAllToasts / SilentObserve gate
                    services.AddSingleton<ToastService>();
                    // v2.2: One-time system scan engine (triggered via IPC from dashboard)
                    services.AddSingleton<ScanEngine>();

                    // Engines
                    services.AddSingleton<TelemetryFusionEngine>();
                    services.AddSingleton<AdvancedResponseEngine>();
                    services.AddSingleton<BehavioralCorrelationEngine>();
                    // v2.0: plugin surface + explainable weighted correlation
                    services.AddSingleton<PluginRegistry>();
                    services.AddSingleton(sp =>
                    {
                        return config.WeightedCorrelation ?? new WeightedCorrelationConfig();
                    });
                    services.AddSingleton<WeightedCorrelationEngine>(sp =>
                        new WeightedCorrelationEngine(
                            sp.GetRequiredService<WeightedCorrelationConfig>(),
                            sp.GetRequiredService<PluginRegistry>(),
                            sp.GetService<ILogger<WeightedCorrelationEngine>>(),
                            sp.GetService<EventGraph>()));
                    services.AddSingleton<AllowlistService>();
                    // v2.8.7: shared runtime blocklist (domains + IPs). Any code can Block/Unblock
                    // at runtime; HostsFileGuard enforces the union with the static config arrays.
                    // Seeds forum.hr as a default block on first run.
                    services.AddSingleton<RuntimeBlocklistService>();
                    services.AddSingleton<SignerTrustService>();
                    services.AddSingleton<ScoringEngine>();
                    services.AddSingleton<ChainTracer>();
                    services.AddSingleton<DllUnloadEngine>();
                    services.AddSingleton<IncidentResponseService>();
                    // v2.6.0: Protective VPN-shield remediation for confirmed network tampering
                    services.AddSingleton<VpnShieldEngine>();

                    // Unified ETW Session - single session subscribing to 9 system providers
                    // Provides event-driven telemetry at ~50ms latency for all monitors
                    services.AddSingleton<UnifiedEtwSession>();
                    services.AddSingleton<EtwEventDispatcher>();

                    // Rules
                    services.AddTransient<IDetectionRule, LsassAccessRule>();
                    services.AddTransient<IDetectionRule, RansomwareDetectionRule>();
                    services.AddTransient<IDetectionRule, ReverseShellRule>();
                    services.AddTransient<IDetectionRule, ThreatIntelInjectionRule>();
                    services.AddTransient<IDetectionRule, PrivilegeEscalationRule>();
                    services.AddTransient<IDetectionRule, AttackToolsRule>();
                    services.AddTransient<IDetectionRule, CampaignIocRule>();
                    services.AddTransient<IDetectionRule, UnsignedBinaryRule>();
                    services.AddTransient<IDetectionRule, IdsCommandLineRule>();
                    services.AddTransient<IDetectionRule, CampaignDetectionRule>();
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

                    // Detection Engine
                    services.AddSingleton<FileReputationEngine>();
                    services.AddSingleton<DetectionEngine>();

                    // v1.3.2: Orchestration layer
                    services.AddSingleton<IncidentManager>();
                    services.AddSingleton<MonitorRegistry>();
                    services.AddSingleton<StartupSequencer>();
                    // v1.3.3: Context Bus + Response Coordinator
                    services.AddSingleton<ContextBus>();
                    services.AddSingleton<ResponseCoordinator>();
                    services.AddSingleton<SentinelOrchestrator>();

                    // IMonitor implementations (started by SentinelService)
                    services.AddSingleton<IMonitor, DnsQueryMonitor>();
                    services.AddSingleton<IMonitor, EtwProcessMonitor>();

                    // Conditional registration for optional monitors
                    if (config.EnableIntelThreatIntel && SystemCapabilities.EtwAvailable)
                        services.AddSingleton<EtwThreatIntelMonitor>();
                    else
                        services.AddSingleton<IMonitor, DisabledMonitor<EtwThreatIntelMonitor>>();

                    if (SystemCapabilities.WmiAvailable)
                        services.AddSingleton<WmiProcessMonitor>();
                    else
                        services.AddSingleton<IMonitor, DisabledMonitor<WmiProcessMonitor>>();

                    services.AddSingleton<FileActivityMonitor>();
                    services.AddSingleton<NetworkMonitor>();
                    services.AddSingleton<LsassDumpCanaryMonitor>();
                    services.AddSingleton<RouteTableMonitor>();
                    services.AddSingleton<MemoryBehaviorAnalyzer>();
                    services.AddSingleton<TokenIntegrityMonitor>();
                    services.AddSingleton<CredentialCanaryMonitor>();
                    services.AddSingleton<LocalServerMonitor>();
                    services.AddSingleton<AppNetworkPolicyMonitor>();

                    // Startup & Health (always start immediately, outside groups)
                    services.AddHostedService<StartupSelfTest>();
                    services.AddHostedService<SentinelHealthCheck>();
                    // One-shot upgrade cleanup: force-delete pre-1.8.8 *.sentinel_verdict pollution
                    services.AddHostedService<LegacyVerdictSidecarPurgeService>();

                    // Core SentinelService (manages IMonitor lifecycle + ProcessAncestryCache)
                    services.AddHostedService<SentinelService>();
                    // v1.9.5: optional Event Log heartbeat (no-ops if Event Log stripped)
                    services.AddHostedService<SentinelEventLogHeartbeatService>();
                    // v2.0: ops metrics snapshot for Agent Ops dashboard
                    services.AddHostedService<OpsMetricsPublisher>();
                    // v2.0: authenticated Service<->Agent named pipe (RT-HIGH-4)
                    services.AddHostedService<ServiceAgentIpcHost>();
                    // v2.0: signed correlation rule packs -> PluginRegistry
                    services.AddHostedService<RulePackLoader>();

                    // 
                    // v1.4.4: Monitor Groups - replaces flat AddHostedService registrations.
                    // Groups provide staggered startup, independent failure restart, and
                    // priority-based ordering. Critical monitors start first with unlimited
                    // restart; peripheral monitors start last with limited restart.
                    // 

                    // Singletons that need to be accessible via DI (referenced by other components)
                    services.AddSingleton<BeaconingDetector>();
                    services.AddSingleton<RansomwareIoMonitor>();
                    services.AddSingleton<BehavioralBaselineService>();
                    services.AddSingleton<PhantomDeviceMonitor>();
                    services.AddSingleton<PersistentConnectionMonitor>();
                    services.AddSingleton<ReinfectionCorrelator>();
                    services.AddSingleton<PseudoSandbox>();
                    services.AddSingleton<IsolationResponseEngine>();

                    //  Group 1: Critical (Self-Protection) 
                    // Starts immediately, restarts indefinitely. These monitors protect
                    // Sentinel itself and must never stay down.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("AntiTamperGuard",             s => s.GetRequiredService<AntiTamperGuard>()),
                            ("IPSecIntegrityGuard",         s => s.GetRequiredService<IPSecIntegrityGuard>()),
                            ("AsrPolicyGuard",              s => s.GetRequiredService<AsrPolicyGuard>()),
                            ("AgentWatchdog",               s => s.GetRequiredService<AgentWatchdog>()),
                            ("SyscallStubMonitor",          s => s.GetRequiredService<SyscallStubMonitor>()),
                            ("ConnectivityCanaryMonitor",   s => s.GetRequiredService<ConnectivityCanaryMonitor>()),
                            ("EtwSessionGuard",             s => s.GetRequiredService<EtwSessionGuard>()),
                            ("EtwProviderTamperMonitor",    s => s.GetRequiredService<EtwProviderTamperMonitor>()),
                            ("HoneypotDllMonitor",          s => s.GetRequiredService<HoneypotDllMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "Critical",
                                Category = MonitorCategory.SystemIntegrity,
                                StartDelay = TimeSpan.Zero,
                                StaggerDelay = TimeSpan.FromMilliseconds(100),
                                RestartIndefinitely = true,
                                RestartCooldown = TimeSpan.FromSeconds(5),
                                HealthCheckInterval = TimeSpan.FromSeconds(15),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    services.AddSingleton<AntiTamperGuard>();
                    services.AddSingleton<IPSecIntegrityGuard>();
                    services.AddSingleton<AsrPolicyGuard>();
                    services.AddSingleton<AgentWatchdog>();
                    services.AddSingleton<SyscallStubMonitor>();
                    services.AddSingleton<ConnectivityCanaryMonitor>();
                    services.AddSingleton<EtwSessionGuard>();
                    services.AddSingleton<EtwProviderTamperMonitor>();
                    services.AddSingleton<HoneypotDllMonitor>();
                    services.AddSingleton<WfpIntegrityMonitor>();
                    services.AddSingleton<DriverLoadMonitor>();

                    //  Group 2: Core Detection 
                    // Starts after self-test (2s delay). Primary behavioral detection.
                    // Restart up to 5 times before degrading.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("RansomwareIoMonitor",          s => s.GetRequiredService<RansomwareIoMonitor>()),
                            ("BeaconingDetector",            s => s.GetRequiredService<BeaconingDetector>()),
                            ("BehavioralBaselineService",    s => s.GetRequiredService<BehavioralBaselineService>()),
                            ("FileVerdictScanner",           s => s.GetRequiredService<FileVerdictScanner>()),
                            ("ConsultantSignalIngestor",     s => s.GetRequiredService<ConsultantSignalIngestor>()),
                            ("GhostProcessMonitor",          s => s.GetRequiredService<GhostProcessMonitor>()),
                            ("EphemeralProcessMonitor",      s => s.GetRequiredService<EphemeralProcessMonitor>()),
                            ("ModuleValidationMonitor",      s => s.GetRequiredService<ModuleValidationMonitor>()),
                            ("RuntimeModuleIntegrityMonitor",s => s.GetRequiredService<RuntimeModuleIntegrityMonitor>()),
                            ("DllEntropyAnalyzer",           s => s.GetRequiredService<DllEntropyAnalyzer>()),
                            ("DllLoadFailureMonitor",        s => s.GetRequiredService<DllLoadFailureMonitor>()),
                            ("DiskWideDllScanner",           s => s.GetRequiredService<DiskWideDllScanner>()),
                            ("DormantPayloadMonitor",        s => s.GetRequiredService<DormantPayloadMonitor>()),
                            ("ComHijackMonitor",             s => s.GetRequiredService<ComHijackMonitor>()),
                            ("PersistentConnectionMonitor",  s => s.GetRequiredService<PersistentConnectionMonitor>()),
                            ("DataExfiltrationMonitor",      s => s.GetRequiredService<DataExfiltrationMonitor>()),
                            ("AdsDataStagingMonitor",        s => s.GetRequiredService<AdsDataStagingMonitor>()),
                            ("ScriptExecutionMonitor",       s => s.GetRequiredService<ScriptExecutionMonitor>()),
                            ("UpdateServicingMonitor",       s => s.GetRequiredService<UpdateServicingMonitor>()),
                            ("ScriptHardeningMonitor",       s => s.GetRequiredService<ScriptHardeningMonitor>()),
                            ("NamedPipeMonitor",             s => s.GetRequiredService<NamedPipeMonitor>()),
                            ("RpcLateralMonitor",            s => s.GetRequiredService<RpcLateralMonitor>()),
                            ("TokenTheftMonitor",            s => s.GetRequiredService<TokenTheftMonitor>()),
                            ("CloudSyncExfilMonitor",        s => s.GetRequiredService<CloudSyncExfilMonitor>()),
                            ("LnkShortcutMonitor",           s => s.GetRequiredService<LnkShortcutMonitor>()),
                            ("AgenticProcessMonitor",        s => s.GetRequiredService<AgenticProcessMonitor>()),
                            ("PackageRuntimeMonitor",        s => s.GetRequiredService<PackageRuntimeMonitor>()),
                            ("LpeScaffoldMonitor",           s => s.GetRequiredService<LpeScaffoldMonitor>()),
                            ("InitialAccessMonitor",         s => s.GetRequiredService<InitialAccessMonitor>()),
                            ("PersistenceSurfaceMonitor",    s => s.GetRequiredService<PersistenceSurfaceMonitor>()),
                            ("DreamJobCampaignMonitor",      s => s.GetRequiredService<DreamJobCampaignMonitor>()),
                            ("EdrKillerDetectionMonitor",    s => s.GetRequiredService<EdrKillerDetectionMonitor>()),
                            ("DecoyPipeMonitor",             s => s.GetRequiredService<DecoyPipeMonitor>()),
                            ("CveClassCoverageMonitor",      s => s.GetRequiredService<CveClassCoverageMonitor>()),
                            ("MotwBypassMonitor",            s => s.GetRequiredService<MotwBypassMonitor>()),
                            ("ContainerIsolationTamperMonitor", s => s.GetRequiredService<ContainerIsolationTamperMonitor>()),
                            ("WpadProxyMonitor",             s => s.GetRequiredService<WpadProxyMonitor>()),
                            ("SensitiveFileAccessMonitor",   s => s.GetRequiredService<SensitiveFileAccessMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "CoreDetection",
                                Category = MonitorCategory.ProcessMonitoring,
                                StartDelay = TimeSpan.FromSeconds(2),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 5,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    services.AddSingleton<FileVerdictScanner>();
                    services.AddSingleton<ConsultantSignalIngestor>();
                    services.AddSingleton<GhostProcessMonitor>(sp =>
                        new GhostProcessMonitor(
                            sp.GetRequiredService<DetectionEngine>(),
                            sp.GetRequiredService<ProcessAncestryCache>(),
                            sp.GetRequiredService<SentinelConfig>(),
                            sp.GetRequiredService<ILogger<GhostProcessMonitor>>(),
                            sp.GetService<PhantomDeviceMonitor>(),
                            sp.GetService<ContextBus>()));
                    services.AddSingleton<EphemeralProcessMonitor>();
                    services.AddSingleton<ModuleValidationMonitor>();
                    services.AddSingleton<RuntimeModuleIntegrityMonitor>();
                    services.AddSingleton<DllEntropyAnalyzer>();
                    services.AddSingleton<DllLoadFailureMonitor>();
                    services.AddSingleton<DiskWideDllScanner>();
                    services.AddSingleton<DormantPayloadMonitor>();
                    services.AddSingleton<ComHijackMonitor>();
                    services.AddSingleton<DataExfiltrationMonitor>();
                    services.AddSingleton<AdsDataStagingMonitor>();
                    services.AddSingleton<ScriptExecutionMonitor>();
                    services.AddSingleton<UpdateServicingMonitor>();
                    services.AddSingleton<ScriptHardeningMonitor>();
                    services.AddSingleton<NamedPipeMonitor>();
                    services.AddSingleton<RpcLateralMonitor>();
                    services.AddSingleton<TokenTheftMonitor>();
                    services.AddSingleton<CloudSyncExfilMonitor>();
                    services.AddSingleton<LnkShortcutMonitor>();
                    services.AddSingleton<AgenticProcessMonitor>();
                    services.AddSingleton<PackageRuntimeMonitor>();
                    services.AddSingleton<LpeScaffoldMonitor>();
                    services.AddSingleton<InitialAccessMonitor>();
                    services.AddSingleton<PersistenceSurfaceMonitor>();
                    services.AddSingleton<DreamJobCampaignMonitor>();
                    services.AddSingleton<EdrKillerDetectionMonitor>();
                    services.AddSingleton<DecoyPipeMonitor>();
                    services.AddSingleton<CveClassCoverageMonitor>();
                    services.AddSingleton<MotwBypassMonitor>();
                    services.AddSingleton<ContainerIsolationTamperMonitor>();
                    services.AddSingleton<WpadProxyMonitor>();
                    services.AddSingleton<SensitiveFileAccessMonitor>();

                    //  Group 3: Credential Protection 
                    // Starts after core detection (4s). Protects credentials and sessions.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("CanaryFileMonitor",               s => s.GetRequiredService<CanaryFileMonitor>()),
                            ("BrowserCredentialGuard",          s => s.GetRequiredService<BrowserCredentialGuard>()),
                            ("BrowserC2Guard",                  s => s.GetRequiredService<BrowserC2Guard>()),
                            ("NativeMessagingHostGuard",        s => s.GetRequiredService<NativeMessagingHostGuard>()),
                            ("LocalControlChannelMonitor",      s => s.GetRequiredService<LocalControlChannelMonitor>()),
                            ("MicrosoftAccountGuardMonitor",    s => s.GetRequiredService<MicrosoftAccountGuardMonitor>()),
                            ("NullSessionGuard",                s => s.GetRequiredService<NullSessionGuard>()),
                            ("BuiltinAdminGuard",               s => s.GetRequiredService<BuiltinAdminGuard>()),
                            ("RemoteLogonHardeningGuard",       s => s.GetRequiredService<RemoteLogonHardeningGuard>()),
                            ("RemoteSessionGuard",              s => s.GetRequiredService<RemoteSessionGuard>()),
                            ("TokenPrivilegeAuditMonitor",      s => s.GetRequiredService<TokenPrivilegeAuditMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "CredentialProtection",
                                Category = MonitorCategory.CredentialProtection,
                                StartDelay = TimeSpan.FromSeconds(4),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    services.AddSingleton<CanaryFileMonitor>();
                    services.AddSingleton<BrowserCredentialGuard>();
                    services.AddSingleton<BrowserC2Guard>();
                    services.AddSingleton<NativeMessagingHostGuard>();
                    services.AddSingleton<LocalControlChannelMonitor>();
                    services.AddSingleton<MicrosoftAccountGuardMonitor>();
                    services.AddSingleton<NullSessionGuard>();
                    services.AddSingleton<BuiltinAdminGuard>();
                    services.AddSingleton<RemoteLogonHardeningGuard>();
                    services.AddSingleton<RemoteSessionGuard>();
                    services.AddSingleton<TokenPrivilegeAuditMonitor>();

                    //  Group 4: Network Integrity 
                    // Starts after credential group (6s). Monitors network-layer attacks.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("ArpSpoofMonitor",                 s => s.GetRequiredService<ArpSpoofMonitor>()),
                            ("DnsResponseValidationMonitor",    s => s.GetRequiredService<DnsResponseValidationMonitor>()),
                            ("PublicIpMonitor",                 s => s.GetRequiredService<PublicIpMonitor>()),
                            ("WifiSecurityMonitor",             s => s.GetRequiredService<WifiSecurityMonitor>()),
                            ("NetworkInterfaceGuard",           s => s.GetRequiredService<NetworkInterfaceGuard>()),
                            ("AppDnsExfilMonitor",              s => s.GetRequiredService<AppDnsExfilMonitor>()),
                            ("NetworkShareMonitor",             s => s.GetRequiredService<NetworkShareMonitor>()),
                            ("NetworkReinfectionDetector",      s => s.GetRequiredService<NetworkReinfectionDetector>()),
                            ("ReinfectionCorrelator",           s => s.GetRequiredService<ReinfectionCorrelator>()),
                            ("DnsCrossValidator",               s => s.GetRequiredService<DnsCrossValidator>()),
                            ("TrafficVolumeBaseline",           s => s.GetRequiredService<TrafficVolumeBaseline>()),
                            ("OutboundConnectionWhitelist",     s => s.GetRequiredService<OutboundConnectionWhitelist>()),
                            ("RemoteAccessMonitor",             s => s.GetRequiredService<RemoteAccessMonitor>()),
                            ("ThreatIntelFeedBlocker",          s => s.GetRequiredService<ThreatIntelFeedBlocker>()),
                            ("ThreatFoxFeedService",            s => s.GetRequiredService<ThreatFoxFeedService>()),
                            ("UdpFlowMonitor",                  s => s.GetRequiredService<UdpFlowMonitor>()),
                            ("IcmpAnomalyMonitor",              s => s.GetRequiredService<IcmpAnomalyMonitor>()),
                            ("WfpNetEventMonitor",              s => s.GetRequiredService<WfpNetEventMonitor>()),
                            ("VoipSessionMonitor",              s => s.GetRequiredService<VoipSessionMonitor>()),
                            ("CovertMeshMonitor",               s => s.GetRequiredService<CovertMeshMonitor>()),
                            ("CovertWebhookMonitor",            s => s.GetRequiredService<CovertWebhookMonitor>()),
                            ("WinsockLspIntegrityMonitor",      s => s.GetRequiredService<WinsockLspIntegrityMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "NetworkIntegrity",
                                Category = MonitorCategory.NetworkMonitoring,
                                StartDelay = TimeSpan.FromSeconds(6),
                                StaggerDelay = TimeSpan.FromMilliseconds(200),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(10),
                                HealthCheckInterval = TimeSpan.FromSeconds(30),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    services.AddSingleton<ArpSpoofMonitor>();
                    services.AddSingleton<DnsResponseValidationMonitor>();
                    services.AddSingleton<PublicIpMonitor>();
                    services.AddSingleton<WifiSecurityMonitor>();
                    services.AddSingleton<NetworkInterfaceGuard>();
                    services.AddSingleton<WinsockLspIntegrityMonitor>();
                    services.AddSingleton<AppDnsExfilMonitor>();
                    services.AddSingleton<NetworkShareMonitor>();
                    services.AddSingleton<NetworkReinfectionDetector>();
                    services.AddSingleton<DnsCrossValidator>();
                    services.AddSingleton<TrafficVolumeBaseline>();
                    services.AddSingleton<OutboundConnectionWhitelist>();
                    services.AddSingleton<RemoteAccessMonitor>();
                    services.AddSingleton<ThreatIntelFeedBlocker>();
                    // GorstaksProtection-ported: ThreatFox hash/domain/IP feed (v2.4.0)
                    services.AddSingleton<ThreatFoxFeedService>();
                    services.AddSingleton<UdpFlowMonitor>();
                    services.AddSingleton<IcmpAnomalyMonitor>();
                    services.AddSingleton<WfpNetEventMonitor>();
                    services.AddSingleton<VoipSessionMonitor>();
                    services.AddSingleton<CovertMeshMonitor>();
                    services.AddSingleton<CovertWebhookMonitor>();

                    //  Group 5: System Integrity 
                    // Starts delayed (10s). Monitors OS-level configuration drift.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("FirewallIntegrityMonitor",        s => s.GetRequiredService<FirewallIntegrityMonitor>()),
                            ("SecureBootIntegrityMonitor",      s => s.GetRequiredService<SecureBootIntegrityMonitor>()),
                            ("WindowsUpdateIntegrityMonitor",   s => s.GetRequiredService<WindowsUpdateIntegrityMonitor>()),
                            ("ScheduledTaskMonitor",            s => s.GetRequiredService<ScheduledTaskMonitor>()),
                            ("CriticalServiceGuard",            s => s.GetRequiredService<CriticalServiceGuard>()),
                            ("RegistryMonitor",                 s => s.GetRequiredService<RegistryMonitor>()),
                            ("WmiPersistenceMonitor",           s => s.GetRequiredService<WmiPersistenceMonitor>()),
                            ("WmiPolicyRewriteMonitor",         s => s.GetRequiredService<WmiPolicyRewriteMonitor>()),
                            ("WorkFoldersExfilMonitor",         s => s.GetRequiredService<WorkFoldersExfilMonitor>()),
                            ("PrivacyServiceOutboundMonitor",   s => s.GetRequiredService<PrivacyServiceOutboundMonitor>()),
                            ("TlsCertificateMonitor",           s => s.GetRequiredService<TlsCertificateMonitor>()),
                            ("UacBypassSurfaceMonitor",         s => s.GetRequiredService<UacBypassSurfaceMonitor>()),
                            ("HostsFileGuard",                  s => s.GetRequiredService<HostsFileGuard>()),
                            ("BrowserDnsPolicyGuard",           s => s.GetRequiredService<BrowserDnsPolicyGuard>()),
                            ("BootIntegrityGuard",              s => s.GetRequiredService<BootIntegrityGuard>()),
                            ("CveShieldHardener",               s => s.GetRequiredService<CveShieldHardener>()),
                            ("ApplicationIntegrityMonitor",     s => s.GetRequiredService<ApplicationIntegrityMonitor>()),
                            ("PseudoSandbox",                   s => s.GetRequiredService<PseudoSandbox>()),
                            ("WfpIntegrityMonitor",             s => s.GetRequiredService<WfpIntegrityMonitor>()),
                            ("DriverLoadMonitor",               s => s.GetRequiredService<DriverLoadMonitor>()),
                            ("GpuProcessMonitor",               s => s.GetRequiredService<GpuProcessMonitor>()),
                            ("WmiProviderIntegrityMonitor",     s => s.GetRequiredService<WmiProviderIntegrityMonitor>()),
                            ("KernelModuleAuditMonitor",        s => s.GetRequiredService<KernelModuleAuditMonitor>()),
                            ("LegacyHiveMonitor",               s => s.GetRequiredService<LegacyHiveMonitor>()),
                            ("CloudFilesHydrationMonitor",      s => s.GetRequiredService<CloudFilesHydrationMonitor>()),
                            ("ClfsExploitationMonitor",         s => s.GetRequiredService<ClfsExploitationMonitor>()),
                            ("StateReconciliationMonitor",      s => s.GetRequiredService<StateReconciliationMonitor>()),
                            ("TrustedHostModuleIntegrityMonitor", s => s.GetRequiredService<TrustedHostModuleIntegrityMonitor>()),
                            ("AggressiveUnsignedDllSweepMonitor", s => s.GetRequiredService<AggressiveUnsignedDllSweepMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "SystemIntegrity",
                                Category = MonitorCategory.SystemIntegrity,
                                StartDelay = TimeSpan.FromSeconds(10),
                                StaggerDelay = TimeSpan.FromMilliseconds(300),
                                MaxRestartAttempts = 3,
                                RestartCooldown = TimeSpan.FromSeconds(15),
                                HealthCheckInterval = TimeSpan.FromSeconds(45),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    // State-baseline reconciliation (drift detection) - observe-only module-inventory
                    // diff of long-lived processes. Reboot-durable baseline store + monitor.
                    services.AddSingleton<ModuleBaselineStore>();
                    services.AddSingleton<StateReconciliationMonitor>();
                    // Registry-driven DLL-load-point integrity (audio APOs + print monitors/processors).
                    // Observe-only (Tier2/LogOnly). Does not duplicate PrintSpoolerMonitor (filesystem
                    // driver store) or WinsockLspIntegrityMonitor (Winsock catalog).
                    services.AddSingleton<IRegisteredModuleSource, HklmRegisteredModuleSource>();
                    services.AddSingleton<TrustedHostModuleIntegrityMonitor>();
                    // Opt-in aggressive unsigned-DLL drive sweep (gated behind
                    // SentinelConfig.EnableAggressiveUnsignedDllSweep, compiled default FALSE).
                    services.AddSingleton<AggressiveUnsignedDllSweepMonitor>();
                    services.AddSingleton<FirewallIntegrityMonitor>();
                    services.AddSingleton<SecureBootIntegrityMonitor>();
                    services.AddSingleton<WindowsUpdateIntegrityMonitor>();
                    services.AddSingleton<ScheduledTaskMonitor>();
                    services.AddSingleton<CriticalServiceGuard>();
                    services.AddSingleton<RegistryMonitor>();
                    services.AddSingleton<WmiPersistenceMonitor>();
                    services.AddSingleton<WmiPolicyRewriteMonitor>();
                    services.AddSingleton<WorkFoldersExfilMonitor>();
                    services.AddSingleton<ServiceProcessMap>();
                    services.AddSingleton<PrivacyServiceOutboundMonitor>();
                    services.AddSingleton<TlsCertificateMonitor>();
                    services.AddSingleton<UacBypassSurfaceMonitor>();
                    services.AddSingleton<HostsFileGuard>();
                    services.AddSingleton<BrowserDnsPolicyGuard>();
                    services.AddSingleton<BootIntegrityGuard>();
                    services.AddSingleton<CveShieldHardener>();
                    services.AddSingleton<ApplicationIntegrityMonitor>();
                    services.AddSingleton<WmiProviderIntegrityMonitor>();
                    services.AddSingleton<GpuProcessMonitor>();
                    services.AddSingleton<KernelModuleAuditMonitor>();
                    services.AddSingleton<LegacyHiveMonitor>();
                    services.AddSingleton<CloudFilesHydrationMonitor>();
                    services.AddSingleton<ClfsExploitationMonitor>();

                    //  Group 6: Peripheral & Environmental 
                    // Starts late (30s). Monitors hardware peripherals and external media.
                    // Lower priority - log and continue on failure.
                    services.AddSingleton<IHostedService>(sp =>
                    {
                        var monitors = SafeMonitorResolver.Build(sp,
                            ("BluetoothMonitor",                s => s.GetRequiredService<BluetoothMonitor>()),
                            ("PhantomDeviceMonitor",            s => s.GetRequiredService<PhantomDeviceMonitor>()),
                            ("DeviceInstallMonitor",            s => s.GetRequiredService<DeviceInstallMonitor>()),
                            ("MtpTransferGuard",                s => s.GetRequiredService<MtpTransferGuard>()),
                            ("VolumeMountMonitor",              s => s.GetRequiredService<VolumeMountMonitor>()),
                            ("CastDeviceGuard",                 s => s.GetRequiredService<CastDeviceGuard>()),
                            ("WslMonitor",                      s => s.GetRequiredService<WslMonitor>()),
                            ("RawDiskAccessMonitor",            s => s.GetRequiredService<RawDiskAccessMonitor>()),
                            ("PrintSpoolerMonitor",             s => s.GetRequiredService<PrintSpoolerMonitor>()),
                            ("SandboxEscapeMonitor",            s => s.GetRequiredService<SandboxEscapeMonitor>()),
                            ("HardwareSecurityGuard",           s => s.GetRequiredService<HardwareSecurityGuard>()),
                            ("UsbHidWhitelist",                 s => s.GetRequiredService<UsbHidWhitelist>()),
                            ("PhysicalAccessMonitor",           s => s.GetRequiredService<PhysicalAccessMonitor>())
                        );
                        return new MonitorGroup(
                            new MonitorGroupConfig
                            {
                                Name = "Peripheral",
                                Category = MonitorCategory.UserProtection,
                                StartDelay = TimeSpan.FromSeconds(30),
                                StaggerDelay = TimeSpan.FromMilliseconds(500),
                                MaxRestartAttempts = 2,
                                RestartCooldown = TimeSpan.FromSeconds(30),
                                HealthCheckInterval = TimeSpan.FromSeconds(45),
                            },
                            monitors,
                            sp.GetRequiredService<ILogger<MonitorGroup>>(),
                            sp.GetRequiredService<MonitorRegistry>());
                    });
                    services.AddSingleton<BluetoothMonitor>();
                    services.AddSingleton<DeviceInstallMonitor>();
                    services.AddSingleton<MtpTransferGuard>();
                    services.AddSingleton<VolumeMountMonitor>();
                    services.AddSingleton<CastDeviceGuard>(sp =>
                        new CastDeviceGuard(
                            sp.GetRequiredService<DetectionEngine>(),
                            sp.GetRequiredService<SentinelConfig>(),
                            sp.GetRequiredService<ILogger<CastDeviceGuard>>(),
                            sp.GetService<PhantomDeviceMonitor>()));
                    services.AddSingleton<WslMonitor>();
                    services.AddSingleton<RawDiskAccessMonitor>();
                    services.AddSingleton<PrintSpoolerMonitor>();
                    services.AddSingleton<SandboxEscapeMonitor>();
                    services.AddSingleton<HardwareSecurityGuard>();
                    services.AddSingleton<UsbHidWhitelist>();
                    services.AddSingleton<PhysicalAccessMonitor>();
                });
    }

    internal sealed class SentinelGuardService : ServiceBase
    {
        private Thread? _thread;
        private volatile bool _stop;

        public SentinelGuardService()
        {
            ServiceName = InstallBootstrap.WatchdogServiceName;
            CanStop = true;
        }

        protected override void OnStart(string[] args)
        {
            _stop = false;
            _thread = new Thread(() =>
            {
                while (!_stop)
                {
                    try { InstallBootstrap.TryStartService(); } catch { }
                    Thread.Sleep(20000);
                }
            })
            { IsBackground = true };
            _thread.Start();
        }

        protected override void OnStop()
        {
            // Cooperative SCM stop of the watchdog - mark expected so any exit hook in this
            // process treats it as a normal lifecycle stop, not a tamper suppression (B1).
            Sentinel.Core.ShutdownContext.MarkExpected(
                Sentinel.Core.ExpectedShutdownReason.ServiceControllerStop);
            _stop = true;
        }
    }
}
