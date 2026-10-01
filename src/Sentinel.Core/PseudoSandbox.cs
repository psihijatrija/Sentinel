using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// PseudoSandbox: Spawns suspicious processes inside a restricted Windows Job Object.
    /// Limits CPU priority, memory usage (64MB), child process count, and UI/clipboard handles.
    /// Monitors the sandbox for an initial 5-second window to detect and contain resource-exhaustion attacks.
    /// </summary>
    public sealed class PseudoSandbox : IHostedService, IDisposable
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<PseudoSandbox> _logger;
        private readonly ConcurrentDictionary<int, SandboxedJobContext> _activeJobs = new();
        private readonly CancellationTokenSource _cts = new();

        public PseudoSandbox(DetectionEngine detectionEngine, ILogger<PseudoSandbox> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("[PseudoSandbox] Started - ready to contain suspicious executions");
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _cts.Cancel();
            foreach (var job in _activeJobs.Values)
            {
                job.Dispose();
            }
            _activeJobs.Clear();
            return Task.CompletedTask;
        }

        /// <summary>
        /// Spawns a process in a restricted Job Object with strict resource limits.
        /// </summary>
        public bool StartProcessInSandbox(string imagePath, string arguments, out int pid)
        {
            pid = 0;
            if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath))
            {
                _logger.LogWarning("[PseudoSandbox] Cannot start: image path '{Path}' does not exist", imagePath);
                return false;
            }

            IntPtr hJob = IntPtr.Zero;
            IntPtr piProcessHandle = IntPtr.Zero;
            IntPtr piThreadHandle = IntPtr.Zero;

            try
            {
                // 1. Create a secure Job Object with randomized name to prevent detection
                // HARDENING v1.3.0: Previously used predictable "SentinelSandboxJob_XXXXXXXX" prefix
                // that malware could enumerate via NtQueryObject to detect sandboxing.
                var jobName = $"WinSvc_{Guid.NewGuid():N}";
                hJob = CreateJobObject(IntPtr.Zero, jobName);
                if (hJob == IntPtr.Zero)
                {
                    _logger.LogError("[PseudoSandbox] CreateJobObject failed: {Error}", Marshal.GetLastWin32Error());
                    return false;
                }

                // 2. Configure Limits: 64MB memory limit, Idle CPU priority, limit active processes to 3
                var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                {
                    BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                    {
                        LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_PRIORITY_CLASS | JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
                        PriorityClass = IDLE_PRIORITY_CLASS,
                        ActiveProcessLimit = 3
                    },
                    ProcessMemoryLimit = new UIntPtr(64 * 1024 * 1024), // 64 MB max per process
                    JobMemoryLimit = new UIntPtr(128 * 1024 * 1024)     // 128 MB max for the whole job
                };

                int size = Marshal.SizeOf(limits);
                IntPtr limitsPtr = Marshal.AllocHGlobal(size);
                try
                {
                    Marshal.StructureToPtr(limits, limitsPtr, false);
                    if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, limitsPtr, (uint)size))
                    {
                        _logger.LogError("[PseudoSandbox] SetInformationJobObject (Limits) failed: {Error}", Marshal.GetLastWin32Error());
                        return false;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(limitsPtr);
                }

                // 3. Configure UI Restrictions: restrict clipboard and desktop handles
                var uiRestrictions = new JOBOBJECT_BASIC_UI_RESTRICTIONS
                {
                    UIRestrictionsClass = JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_WRITECLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                };

                int uiSize = Marshal.SizeOf(uiRestrictions);
                IntPtr uiPtr = Marshal.AllocHGlobal(uiSize);
                try
                {
                    Marshal.StructureToPtr(uiRestrictions, uiPtr, false);
                    if (!SetInformationJobObject(hJob, JobObjectBasicUIRestrictions, uiPtr, (uint)uiSize))
                    {
                        _logger.LogWarning("[PseudoSandbox] SetInformationJobObject (UI) failed: {Error}", Marshal.GetLastWin32Error());
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(uiPtr);
                }

                // 3.5. Configure Security Restrictions: strip administrator privileges and filter token rights
                var securityLimits = new JOBOBJECT_SECURITY_LIMIT_INFORMATION
                {
                    SecurityLimitFlags = JOB_OBJECT_SECURITY_NO_ADMIN | JOB_OBJECT_SECURITY_FILTER_TOKENS
                };

                int secSize = Marshal.SizeOf(securityLimits);
                IntPtr secPtr = Marshal.AllocHGlobal(secSize);
                try
                {
                    Marshal.StructureToPtr(securityLimits, secPtr, false);
                    if (!SetInformationJobObject(hJob, JobObjectSecurityLimitInformation, secPtr, (uint)secSize))
                    {
                        _logger.LogWarning("[PseudoSandbox] SetInformationJobObject (Security) failed: {Error}", Marshal.GetLastWin32Error());
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(secPtr);
                }

                // 4. Start process suspended to prevent escape before assignment
                var si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                var pi = new PROCESS_INFORMATION();

                string cmdLine = $"\"{imagePath}\" {arguments}";

                bool success = CreateProcess(
                    null,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi
                );

                if (!success)
                {
                    _logger.LogError("[PseudoSandbox] CreateProcess failed: {Error}", Marshal.GetLastWin32Error());
                    return false;
                }

                piProcessHandle = pi.hProcess;
                piThreadHandle = pi.hThread;
                pid = pi.dwProcessId;

                // 5. Assign process to Job Object
                if (!AssignProcessToJobObject(hJob, pi.hProcess))
                {
                    _logger.LogError("[PseudoSandbox] AssignProcessToJobObject failed: {Error}", Marshal.GetLastWin32Error());
                    TerminateProcess(pi.hProcess, 1);
                    return false;
                }

                // 6. Resume thread execution
                ResumeThread(pi.hThread);
                _logger.LogInformation("[PseudoSandbox] Process '{Path}' (PID {Pid}) successfully contained in sandbox job", Path.GetFileName(imagePath), pid);

                // Register context for monitoring
                var jobCtx = new SandboxedJobContext(hJob, pi.hProcess, imagePath, pid);
                _activeJobs[pid] = jobCtx;

                // Fire background monitoring thread
                _ = Task.Run(() => MonitorJobAsync(jobCtx, _cts.Token));

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PseudoSandbox] Error spawning process in sandbox");
                if (piProcessHandle != IntPtr.Zero) TerminateProcess(piProcessHandle, 1);
                if (hJob != IntPtr.Zero) CloseHandle(hJob);
                return false;
            }
            finally
            {
                if (piThreadHandle != IntPtr.Zero) CloseHandle(piThreadHandle);
            }
        }

        private async Task MonitorJobAsync(SandboxedJobContext ctx, CancellationToken ct)
        {
            var stopwatch = Stopwatch.StartNew();
            _logger.LogDebug("[PseudoSandbox] Monitoring job for process {Path} (PID {Pid})", ctx.ProcessName, ctx.Pid);

            try
            {
                while (stopwatch.Elapsed.TotalSeconds < 5 && !ct.IsCancellationRequested)
                {
                    await Task.Delay(500, ct);

                    // Check if process has exited
                    if (GetExitCodeProcess(ctx.ProcessHandle, out uint exitCode) && exitCode != STILL_ACTIVE)
                    {
                        _logger.LogInformation("[PseudoSandbox] Process '{Name}' (PID {Pid}) exited cleanly inside sandbox", ctx.ProcessName, ctx.Pid);
                        break;
                    }

                    // Query Job Object statistics (e.g. PeakMemoryUsage, CPU usage, process count)
                    var basicInfo = new JOBOBJECT_BASIC_ACCOUNTING_INFORMATION();
                    int size = Marshal.SizeOf(basicInfo);
                    IntPtr infoPtr = Marshal.AllocHGlobal(size);
                    try
                    {
                        if (QueryInformationJobObject(ctx.JobHandle, JobObjectBasicAccountingInformation, infoPtr, (uint)size, out _))
                        {
                            basicInfo = Marshal.PtrToStructure<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>(infoPtr);
                            if (basicInfo.ActiveProcesses > 3)
                            {
                                await TerminateViolatingJobAsync(ctx, "Active process count limit exceeded (possible fork bomb).");
                                break;
                            }
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(infoPtr);
                    }

                    // Check memory limits directly on the process as a secondary safeguard
                    try
                    {
                        using var proc = Process.GetProcessById(ctx.Pid);
                        long workingSet = proc.WorkingSet64;
                        if (workingSet > 64 * 1024 * 1024)
                        {
                            await TerminateViolatingJobAsync(ctx, $"Memory threshold exceeded: {(workingSet / 1024 / 1024)}MB (max 64MB).");
                            break;
                        }
                    }
                    catch
                    {
                        // Process may have exited during query
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[PseudoSandbox] Monitor error");
            }
            finally
            {
                _activeJobs.TryRemove(ctx.Pid, out _);
                ctx.Dispose();
            }
        }

        private async Task TerminateViolatingJobAsync(SandboxedJobContext ctx, string reason)
        {
            _logger.LogWarning("[PseudoSandbox] TERMINATING contained job (PID {Pid}) for resource policy violation: {Reason}", ctx.Pid, reason);

            // Terminate all processes in the job
            TerminateJobObject(ctx.JobHandle, 2);

            // Emit a Tier 1 behavioral detection
            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Sandbox Abuse: Containment Limits Exceeded",
                Evidence = $"Process '{ctx.ProcessName}' (PID {ctx.Pid}) exceeded sandbox resource boundaries: {reason}",
                Reasoning = "The process was executing inside the restricted PseudoSandbox and attempted to consume resources beyond allowed limits (e.g. memory leak, zip bomb expansion, or process spawning), triggering automatic job termination.",
                Confidence = 0.95,
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.LogOnly, // Already terminated via TerminateJobObject
                ProcessName = ctx.ProcessName,
                ProcessId = ctx.Pid,
                SignalType = SignalType.SuspiciousProcess
            });
        }

        public void Dispose()
        {
            _cts.Dispose();
            GC.SuppressFinalize(this);
        }

        private sealed class SandboxedJobContext : IDisposable
        {
            public IntPtr JobHandle { get; }
            public IntPtr ProcessHandle { get; }
            public string ProcessName { get; }
            public int Pid { get; }

            public SandboxedJobContext(IntPtr jobHandle, IntPtr processHandle, string imagePath, int pid)
            {
                JobHandle = jobHandle;
                ProcessHandle = processHandle;
                ProcessName = Path.GetFileName(imagePath);
                Pid = pid;
            }

            public void Dispose()
            {
                if (JobHandle != IntPtr.Zero) CloseHandle(JobHandle);
                if (ProcessHandle != IntPtr.Zero) CloseHandle(ProcessHandle);
            }
        }

        // --- Win32 P/Invokes and constants ---
        private const uint JobObjectBasicUIRestrictions = 2;
        private const uint JobObjectBasicAccountingInformation = 1;
        private const uint JobObjectExtendedLimitInformation = 9;

        private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
        private const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;
        private const uint JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000010;
        private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;

        private const uint JOB_OBJECT_UILIMIT_HANDLES = 0x00000001;
        private const uint JOB_OBJECT_UILIMIT_READCLIPBOARD = 0x00000002;
        private const uint JOB_OBJECT_UILIMIT_WRITECLIPBOARD = 0x00000004;
        private const uint JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS = 0x00000008;

        private const uint IDLE_PRIORITY_CLASS = 0x00000040;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
        private const uint STILL_ACTIVE = 259;

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(IntPtr hJob, uint JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryInformationJobObject(IntPtr hJob, uint JobObjectInformationClass, IntPtr lpJobObjectInformation, uint cbJobObjectInformationLength, out uint lpReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateJobObject(IntPtr hJob, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_UI_RESTRICTIONS
        {
            public uint UIRestrictionsClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION
        {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_SECURITY_LIMIT_INFORMATION
        {
            public uint SecurityLimitFlags;
            public IntPtr JobToken;
            public IntPtr SidsToDisable;
            public IntPtr PrivilegesToDelete;
            public IntPtr SidsToRestricted;
        }

        private const uint JobObjectSecurityLimitInformation = 5;
        private const uint JOB_OBJECT_SECURITY_NO_ADMIN = 0x00000001;
        private const uint JOB_OBJECT_SECURITY_FILTER_TOKENS = 0x00000008;
    }
}
