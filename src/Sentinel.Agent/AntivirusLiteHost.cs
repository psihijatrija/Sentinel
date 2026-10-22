using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;

namespace Sentinel.Agent
{
    /// <summary>
    /// Hosts the standalone <c>AntivirusLite.ps1</c> engine IN-PROCESS inside
    /// Sentinel.Agent.exe using the Windows PowerShell 5.1 runtime
    /// (System.Management.Automation, present in the GAC on every supported
    /// Windows box - nothing extra is shipped).
    ///
    /// Why in-process instead of launching powershell.exe:
    /// a visible PowerShell process in Task Manager tends to alarm users. By
    /// hosting the engine in a Runspace on a dedicated background thread, the
    /// script's monitors run entirely within the Agent process - there is NO
    /// separate powershell.exe for a user to see.
    ///
    /// The script is launched with -Embedded, which disables its two
    /// Start-Job-based scanners (the only paths that would spawn a child
    /// powershell.exe) and its scheduled-task auto-start. All other monitors
    /// (file watcher, WMI exec monitor, scored C2 engine, reverse-shell killer)
    /// run on this host thread.
    ///
    /// REMOVAL: this module is deliberately self-contained and decoupled from
    /// Sentinel's response-policy pipeline (same spirit as modules\NanoAV). To
    /// remove it entirely: delete this file, delete the modules\AntivirusLite
    /// folder, remove the single AddHostedService line in Program.cs, and drop
    /// the csproj content-copy + installer [Files] line. No other code depends
    /// on it.
    /// </summary>
    public sealed class AntivirusLiteHost : IHostedService, IDisposable
    {
        // Master switch. Flip to false to disable the module without removing it.
        // static readonly (not const) so the Enabled==false guard below does not
        // trip CS0162 unreachable-code warnings.
        private static readonly bool Enabled = true;

        private const string ScriptRelativePath = @"modules\AntivirusLite\AntivirusLite.ps1";

        private Thread? _engineThread;
        private Runspace? _runspace;
        private PowerShell? _ps;
        private readonly CancellationTokenSource _cts = new();
        private volatile bool _stopping;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!Enabled)
            {
                Log("AntivirusLite module disabled (Enabled=false) - not starting.");
                return Task.CompletedTask;
            }

            var scriptPath = ResolveScriptPath();
            if (scriptPath == null)
            {
                Log($"AntivirusLite script not found (looked for '{ScriptRelativePath}' near the agent) - module inactive.");
                return Task.CompletedTask;
            }

            // The script's main body ends in an infinite while($true) loop, so the
            // pipeline invocation never returns until the runspace is torn down.
            // Run it on a dedicated background thread so it cannot block host startup.
            _engineThread = new Thread(() => RunEngine(scriptPath))
            {
                IsBackground = true,
                Name = "AntivirusLiteEngine"
            };
            _engineThread.SetApartmentState(ApartmentState.MTA);
            _engineThread.Start();

            Log($"AntivirusLite engine started in-process (script: {scriptPath}).");
            return Task.CompletedTask;
        }

        private void RunEngine(string scriptPath)
        {
            try
            {
                // CreateDefault2() builds a MINIMAL session (core snap-in +
                // module autoloading) and - critically - does NOT eagerly load
                // the WSMan/remoting snap-in. CreateDefault() tries to load
                // Microsoft.WSMan.Management, which fails to resolve
                // Microsoft.WSMan.dll in this hosted (non-powershell.exe) context
                // and throws PSSnapInException on Open(). The script only needs
                // core + autoloaded cmdlets (Get-FileHash, Get-NetTCPConnection,
                // Get-CimInstance, Register-WmiEvent, New-NetFirewallRule, ...),
                // all of which resolve under CreateDefault2().
                var iss = InitialSessionState.CreateDefault2();

                _runspace = RunspaceFactory.CreateRunspace(iss);
                _runspace.Open();

                _ps = PowerShell.Create();
                _ps.Runspace = _runspace;

                // Allow the script to run regardless of machine execution policy;
                // we are executing a file we ship, not arbitrary downloaded code.
                // Set-ExecutionPolicy at Process scope applies only to this hosted
                // runspace and does not alter machine/user policy. Run it, clear the
                // pipeline, then invoke the script.
                _ps.AddScript("Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue");
                _ps.Invoke();
                _ps.Commands.Clear();

                // Invoke the script file with -Embedded (suppresses the
                // Start-Job scanners + scheduled-task auto-start) and -SentinelDir
                // (the agent install directory). The script treats everything
                // under SentinelDir, and the Sentinel process names, as off-limits
                // for quarantine/delete/kill - otherwise the embedded AV flags
                // Sentinel.Agent.exe / Sentinel.Service.exe as malware and kills
                // its own host.
                var sentinelDir = AppContext.BaseDirectory.TrimEnd('\\');
                _ps.AddCommand(scriptPath)
                   .AddParameter("Embedded", true)
                   .AddParameter("SentinelDir", sentinelDir);

                // Surface script-side errors into the agent crash log without
                // throwing out of the host.
                _ps.Streams.Error.DataAdded += (s, e) =>
                {
                    try
                    {
                        var rec = _ps?.Streams.Error[e.Index];
                        if (rec != null) Log($"[ps-error] {rec}");
                    }
                    catch { }
                };

                // Blocks here for the life of the process (script loops forever).
                _ps.Invoke();
            }
            catch (Exception ex)
            {
                if (!_stopping)
                    Log($"AntivirusLite engine terminated unexpectedly: {ex.Message}");
            }
        }

        /// <summary>
        /// Resolve the script next to the agent executable (installed layout:
        /// the installer copies the modules folder beside Sentinel.Agent.exe),
        /// then fall back to the repo layout for dev runs.
        /// </summary>
        private static string? ResolveScriptPath()
        {
            var baseDir = AppContext.BaseDirectory;

            var candidates = new[]
            {
                Path.Combine(baseDir, ScriptRelativePath),
                // Dev / repo fallback: src\Sentinel.Agent\bin\...  ->  repo root
                Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", ScriptRelativePath)),
            };

            foreach (var c in candidates)
            {
                if (File.Exists(c)) return c;
            }
            return null;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _stopping = true;
            try { _cts.Cancel(); } catch { }

            // Stopping the pipeline unwinds the script's infinite loop; closing
            // the runspace releases the engine. The monitors the script
            // registered (FileSystemWatcher, WMI events) are torn down when the
            // runspace closes.
            try { _ps?.Stop(); } catch { }
            try { _runspace?.Close(); } catch { }

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            try { _ps?.Dispose(); } catch { }
            try { _runspace?.Dispose(); } catch { }
            try { _cts.Dispose(); } catch { }
        }

        private static void Log(string message)
        {
            try
            {
                var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                var dir = Path.Combine(programData, "Sentinel");
                Directory.CreateDirectory(dir);
                var logPath = Path.Combine(dir, "antiviruslite_host.log");
                File.AppendAllText(logPath, $"[{DateTime.UtcNow:o}] {message}{Environment.NewLine}");
            }
            catch { }
        }
    }
}
