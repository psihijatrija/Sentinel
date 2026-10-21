using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace NanoAV
{
    // Self-PID registry. Mirrors Register-OwnPid / Remove-DeadOwnPids /
    // Get-OwnPidSet. Uses a named mutex just like the original script so the
    // shared PID file is safe across the main process and worker threads.
    internal static class PidRegistry
    {
        private const string MutexName = @"Global\NanoAV_PidFile";

        public static void RegisterOwnPid(int processId)
        {
            Mutex mutex = null;
            try
            {
                mutex = new Mutex(false, MutexName);
                try { mutex.WaitOne(2000); } catch (AbandonedMutexException) { }
                try
                {
                    File.AppendAllText(Config.OwnPidFile, processId + Environment.NewLine);
                }
                catch { }
            }
            catch { }
            finally
            {
                if (mutex != null) { try { mutex.ReleaseMutex(); } catch { } mutex.Dispose(); }
            }
        }

        public static void RegisterSelf()
        {
            RegisterOwnPid(Process.GetCurrentProcess().Id);
        }

        public static void RemoveDeadOwnPids()
        {
            Mutex mutex = null;
            try
            {
                mutex = new Mutex(false, MutexName);
                try { mutex.WaitOne(2000); } catch (AbandonedMutexException) { }

                if (!File.Exists(Config.OwnPidFile)) return;

                var alive = new HashSet<int>();
                foreach (string line in File.ReadAllLines(Config.OwnPidFile))
                {
                    int n;
                    if (int.TryParse(line.Trim(), out n))
                    {
                        if (ProcessExists(n)) alive.Add(n);
                    }
                }
                alive.Add(Process.GetCurrentProcess().Id);

                var sorted = new List<int>(alive);
                sorted.Sort();
                File.WriteAllLines(Config.OwnPidFile, sorted.ConvertAll(x => x.ToString()).ToArray());
            }
            catch { }
            finally
            {
                if (mutex != null) { try { mutex.ReleaseMutex(); } catch { } mutex.Dispose(); }
            }
        }

        // Hashtable of NanoAV-owned PIDs so engines never kill the NanoAV itself.
        public static HashSet<int> GetOwnPidSet()
        {
            var own = new HashSet<int> { Process.GetCurrentProcess().Id };
            // Coexistence only: C2/reverse-shell paths already skip this returned set.
            foreach (Process process in Process.GetProcesses())
            {
                using (process)
                    if (SentinelCoexistence.IsProtectedProcess(process)) own.Add(process.Id);
            }
            try
            {
                if (File.Exists(Config.OwnPidFile))
                {
                    foreach (string line in File.ReadAllLines(Config.OwnPidFile))
                    {
                        int n;
                        if (int.TryParse(line.Trim(), out n)) own.Add(n);
                    }
                }
            }
            catch { }
            return own;
        }

        private static bool ProcessExists(int pid)
        {
            try { Process.GetProcessById(pid); return true; }
            catch { return false; }
        }
    }
}
