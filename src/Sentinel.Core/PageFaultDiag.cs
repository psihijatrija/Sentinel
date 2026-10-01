using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;

namespace Sentinel.Core
{
    /// <summary>
    /// Isolated hard-fault attribution. Invoked as
    /// <c>Sentinel.Service.exe --pagefault-diag</c> - does not start monitors
    /// or take response actions. Replays the service's real scan kernels and
    /// records LatencyMon-equivalent <see cref="HardFaultProbe"/> deltas.
    /// </summary>
    public static class PageFaultDiag
    {
        /// <summary>
        /// Sample a live process: <c>Sentinel.Service.exe --pagefault-watch &lt;pid&gt; [seconds]</c>
        /// Default 60s, 5s interval. Does not start monitors.
        /// </summary>
        public static int Watch(string[] args)
        {
            if (args.Length < 2 || !int.TryParse(args[1], out int pid) || pid <= 0)
            {
                Console.Error.WriteLine("usage: Sentinel.Service.exe --pagefault-watch <pid> [seconds]");
                return 1;
            }

            int seconds = 60;
            if (args.Length >= 3 && int.TryParse(args[2], out int s) && s > 0)
                seconds = Math.Min(s, 600);

            const int intervalMs = 5000;
            Console.WriteLine($"Watching PID {pid} for {seconds}s (HardFaultCount, 5s samples)");
            Console.WriteLine("Does not start Sentinel. Ctrl+C to stop.");
            Console.WriteLine("");
            Console.WriteLine($"{"sec",4} {"hard",8} {"dHard",6} {"WS_MB",8}");

            uint prev = 0;
            bool havePrev = false;
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds <= seconds)
            {
                if (!HardFaultProbe.TryGetHardFaultCount(pid, out uint hard))
                {
                    Console.WriteLine($"t={sw.Elapsed.TotalSeconds:F0}s  failed to read HardFaultCount (process gone?)");
                    return 2;
                }

                long ws = 0;
                try { ws = Process.GetProcessById(pid).WorkingSet64; } catch { /* gone */ }

                uint delta = havePrev && hard >= prev ? hard - prev : 0;
                Console.WriteLine($"{(int)sw.Elapsed.TotalSeconds,4} {hard,8} {delta,6} {(ws / (1024.0 * 1024.0)),8:F1}");
                prev = hard;
                havePrev = true;
                Thread.Sleep(intervalMs);
            }

            return 0;
        }

        public static int Run(string[] args)
        {
            var sb = new StringBuilder();
            void Line(string s)
            {
                Console.WriteLine(s);
                sb.AppendLine(s);
            }

            Line("Sentinel hard-page-fault diagnostic");
            Line($"UTC {DateTime.UtcNow:O}");
            Line($"PID {Process.GetCurrentProcess().Id}  bitness {(IntPtr.Size == 8 ? "x64" : "x86")}");
            Line("Metric: SYSTEM_PROCESS_INFORMATION.HardFaultCount (same counter LatencyMon uses).");
            Line("No monitors started. No process kill / quarantine.");
            Line("");

            var baseline = HardFaultProbe.ReadCurrent();
            if (!baseline.HardFaultsValid)
            {
                Line("WARNING: HardFaultCount parse failed - reporting total PageFaultCount only.");
                Line("Fix the probe before trusting these numbers against LatencyMon.");
            }
            else
            {
                Line($"Probe OK. Starting HardFaults={baseline.HardFaults}  PageFaults={baseline.PageFaults}  WS={Mb(baseline.WorkingSetBytes)}");
            }

            Line("");
            Line(FormatRow("Phase", "Hard", "Page", "WS_MB", "Detail"));
            Line(new string('-', 100));

            // JIT the probe + Process APIs so first-call faults are not blamed on a phase.
            Warmup();

            RunPhase(Line, "idle-10s", () => Thread.Sleep(10_000));

            RunPhase(Line, "GetProcesses x30", () =>
            {
                int n = 0;
                for (int i = 0; i < 30; i++)
                {
                    var procs = Process.GetProcesses();
                    n = procs.Length;
                    foreach (var p in procs) p.Dispose();
                }
                return $"{n} processes";
            });

            RunPhase(Line, "GetProcessImagePath all x5", () =>
            {
                int ok = 0;
                for (int i = 0; i < 5; i++)
                {
                    foreach (var p in Process.GetProcesses())
                    {
                        try
                        {
                            if (!string.IsNullOrEmpty(SecurityValidation.GetProcessImagePath(p.Id)))
                                ok++;
                        }
                        catch { /* access */ }
                        finally { p.Dispose(); }
                    }
                }
                return $"{ok} path lookups";
            });

            List<(int Pid, string Name, string Path)> inspectable = SnapshotInspectable();
            Line($"  (inspectable PIDs this run: {inspectable.Count})");

            RunPhase(Line, "EnumModules inspectable x3", () =>
            {
                int mods = 0;
                for (int i = 0; i < 3; i++)
                {
                    foreach (var t in inspectable)
                        mods += NativeProcessMemory.EnumModules(t.Pid).Count;
                }
                return $"{mods} module records (3 passes)";
            });

            RunPhase(Line, "ModuleIdentity.Evaluate x3", () =>
            {
                int evals = 0;
                for (int i = 0; i < 3; i++)
                {
                    foreach (var t in inspectable)
                    {
                        foreach (var mod in NativeProcessMemory.EnumModules(t.Pid))
                        {
                            _ = ModuleIdentity.Evaluate(t.Path, mod.Path, _ => false);
                            evals++;
                        }
                    }
                }
                return $"{evals} verdicts";
            });

            RunPhase(Line, "Authenticode process images (cold)", () =>
            {
                var paths = inspectable
                    .Select(t => t.Path)
                    .Where(p => !string.IsNullOrEmpty(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                int signed = 0;
                foreach (var path in paths)
                {
                    if (SecurityValidation.VerifyAuthenticodeSignature(path))
                        signed++;
                }
                return $"{signed}/{paths.Count} signed";
            });

            RunPhase(Line, "Authenticode process images (warm)", () =>
            {
                var paths = inspectable
                    .Select(t => t.Path)
                    .Where(p => !string.IsNullOrEmpty(p))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                int signed = 0;
                foreach (var path in paths)
                {
                    if (SecurityValidation.VerifyAuthenticodeSignature(path))
                        signed++;
                }
                return $"{signed}/{paths.Count} signed";
            });

            RunPhase(Line, "VirtualQueryEx walk (no RPM)", () =>
            {
                int regions = 0, opened = 0;
                foreach (var t in inspectable)
                {
                    var h = NativeProcessMemory.OpenRemoteHandle(
                        NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ,
                        t.Pid);
                    if (h == IntPtr.Zero) continue;
                    opened++;
                    try { regions += CountRegions(h, readPrivateRx: false); }
                    finally { NativeProcessMemory.CloseHandle(h); }
                }
                return $"{opened} procs, {regions} regions";
            });

            RunPhase(Line, "Hell's Gate replica (Query+RPM private RX<=64K)", () =>
            {
                int reads = 0, opened = 0;
                foreach (var t in inspectable)
                {
                    var h = NativeProcessMemory.OpenRemoteHandle(
                        NativeProcessMemory.PROCESS_QUERY_INFORMATION | NativeProcessMemory.PROCESS_VM_READ,
                        t.Pid);
                    if (h == IntPtr.Zero) continue;
                    opened++;
                    try { reads += CountRegions(h, readPrivateRx: true); }
                    finally { NativeProcessMemory.CloseHandle(h); }
                }
                return $"{opened} procs, {reads} RPM of small private RX";
            });

            RunPhase(Line, "SHA256 ntdll+kernel32 x8 (SyscallStubMonitor disk hash)", () =>
            {
                var ntdll = Path.Combine(Environment.SystemDirectory, "ntdll.dll");
                var k32 = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
                int hashes = 0;
                for (int i = 0; i < 8; i++)
                {
                    hashes += HashFile(ntdll) ? 1 : 0;
                    hashes += HashFile(k32) ? 1 : 0;
                }
                return $"{hashes} hashes";
            });

            Line("");
            Line("Historical MBA shape (GetProcesses + EnumModules + identity), 6 cycles @ 5s.");
            Line("Pre-2.4.6 poll - live MBA is one baseline then ImageLoad. No DllUnload / no kill.");
            for (int cycle = 1; cycle <= 6; cycle++)
            {
                int cycleCapture = cycle;
                RunPhase(Line, $"MBA-like cycle {cycleCapture}", () =>
                {
                    int procs = 0, mods = 0;
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            if (proc.Id <= 4) continue;
                            var path = SecurityValidation.GetProcessImagePath(proc.Id);
                            if (SecurityValidation.IsGameOrAntiCheatProcess(proc.Id, path) ||
                                !NativeProcessMemory.CanInspect(proc.Id, path))
                                continue;
                            procs++;
                            foreach (var mod in NativeProcessMemory.EnumModules(proc.Id))
                            {
                                _ = ModuleIdentity.Evaluate(path, mod.Path, _ => false);
                                mods++;
                            }
                        }
                        catch { /* access */ }
                        finally { proc.Dispose(); }
                    }
                    Thread.Sleep(5000);
                    return $"{procs} inspectable, {mods} modules";
                });
            }

            Line("");
            Line("Trim experiment: EmptyWorkingSet then one MBA-like cycle (no 5s wait).");
            Line("If this dwarfs the cycles above, the OS is paging Sentinel itself.");
            RunPhase(Line, "EmptyWorkingSet", () =>
            {
                using var proc = Process.GetCurrentProcess();
                bool ok = HardFaultProbe.EmptyWorkingSet(proc.Handle);
                Thread.Sleep(200);
                return ok ? "trimmed" : "EmptyWorkingSet failed";
            });

            RunPhase(Line, "MBA-like after trim", () =>
            {
                int procs = 0, mods = 0;
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id <= 4) continue;
                        var path = SecurityValidation.GetProcessImagePath(proc.Id);
                        if (!NativeProcessMemory.CanInspect(proc.Id, path)) continue;
                        procs++;
                        mods += NativeProcessMemory.EnumModules(proc.Id).Count;
                    }
                    catch { /* access */ }
                    finally { proc.Dispose(); }
                }
                return $"{procs} inspectable, {mods} modules";
            });

            var end = HardFaultProbe.ReadCurrent();
            var total = HardFaultProbe.Snapshot.Delta(baseline, end);
            Line("");
            Line($"TOTAL  Hard={FmtHard(total)}  Page={total.PageFaults}  end WS={Mb(end.WorkingSetBytes)}");
            Line("");
            Line("How to read this:");
            Line("- Hard is what LatencyMon counts. 300 in <1 min is ~5/s.");
            Line("- If MBA-like cycles are already tens of Hard each, that loop is the production leak.");
            Line("- If only EmptyWorkingSet + after-trim is huge, lock/pin the service working set.");
            Line("- Authenticode cold vs warm isolates WinVerifyTrust file maps.");
            Line("- Hell's Gate replica isolates ReadProcessMemory of other processes.");

            var outPath = Path.Combine(
                Path.GetTempPath(),
                $"sentinel-pagefault-diag-{DateTime.UtcNow:yyyyMMdd-HHmmss}.txt");
            try
            {
                File.WriteAllText(outPath, sb.ToString());
                Line("");
                Line($"Wrote {outPath}");
            }
            catch (Exception ex)
            {
                Line($"Could not write report: {ex.Message}");
            }

            return 0;
        }

        private static void Warmup()
        {
            _ = HardFaultProbe.ReadCurrent();
            foreach (var p in Process.GetProcesses()) p.Dispose();
            _ = SecurityValidation.GetProcessImagePath(Process.GetCurrentProcess().Id);
            _ = NativeProcessMemory.EnumModules(Process.GetCurrentProcess().Id);
            string? selfPath = null;
            try { selfPath = Process.GetCurrentProcess().MainModule?.FileName; } catch { /* restricted */ }
            _ = ModuleIdentity.Evaluate(
                selfPath,
                typeof(PageFaultDiag).Assembly.Location,
                _ => false);
        }

        private static List<(int Pid, string Name, string Path)> SnapshotInspectable()
        {
            var list = new List<(int, string, string)>();
            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Id <= 4) continue;
                    var path = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!NativeProcessMemory.CanInspect(proc.Id, path)) continue;
                    list.Add((proc.Id, proc.ProcessName, path ?? ""));
                }
                catch { /* access */ }
                finally { proc.Dispose(); }
            }
            return list;
        }

        private static int CountRegions(IntPtr hProcess, bool readPrivateRx)
        {
            IntPtr address = IntPtr.Zero;
            int regions = 0;
            int reads = 0;
            const uint memPrivate = 0x20000;
            const long maxHellsGate = 64 * 1024;
            while (regions < 5000)
            {
                regions++;
                int n = NativeProcessMemory.QueryRemoteRegion(hProcess, address, out var mbi);
                if (n == 0) break;
                long regionSize = (long)mbi.RegionSize;
                if (readPrivateRx &&
                    mbi.State == NativeProcessMemory.MEM_COMMIT &&
                    mbi.Type == memPrivate &&
                    NativeProcessMemory.IsExecutableProtection(mbi.Protect) &&
                    regionSize > 0 && regionSize <= maxHellsGate)
                {
                    var buffer = new byte[(int)regionSize];
                    if (NativeProcessMemory.CopyRemote(hProcess, mbi.BaseAddress, buffer, out _))
                        reads++;
                }

                ulong nextAddr = (ulong)mbi.BaseAddress + (ulong)mbi.RegionSize;
                if (nextAddr <= (ulong)address) break;
                address = (IntPtr)nextAddr;
            }

            return readPrivateRx ? reads : regions;
        }

        private static bool HashFile(string path)
        {
            try
            {
                if (!File.Exists(path)) return false;
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                _ = Sha256Net48.HashData(fs);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static void RunPhase(Action<string> line, string name, Action body)
        {
            RunPhase(line, name, () =>
            {
                body();
                return "";
            });
        }

        private static void RunPhase(Action<string> line, string name, Func<string> body)
        {
            GC.Collect(0, GCCollectionMode.Optimized, blocking: false);
            Thread.Sleep(50);
            var before = HardFaultProbe.ReadCurrent();
            string detail;
            try { detail = body() ?? ""; }
            catch (Exception ex) { detail = "EX: " + ex.GetType().Name + " " + ex.Message; }
            var after = HardFaultProbe.ReadCurrent();
            var d = HardFaultProbe.Snapshot.Delta(before, after);
            line(FormatRow(name, FmtHard(d), d.PageFaults.ToString(), Mb(after.WorkingSetBytes), detail));
        }

        private static string FmtHard(HardFaultProbe.Snapshot d) =>
            d.HardFaultsValid ? d.HardFaults.ToString() : "n/a";

        private static string Mb(long bytes) => (bytes / (1024.0 * 1024.0)).ToString("F1");

        private static string FormatRow(string phase, string hard, string page, string ws, string detail) =>
            $"{Pad(phase, 52)} {Pad(hard, 7)} {Pad(page, 7)} {Pad(ws, 7)} {detail}";

        private static string Pad(string s, int n) =>
            s.Length >= n ? s : s + new string(' ', n - s.Length);
    }
}
