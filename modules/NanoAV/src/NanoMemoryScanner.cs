using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace NanoAV
{
    // Start-MemoryScanner: periodic string/module heuristic scan over every
    // process the NanoAV did not spawn. Runs on a background thread (the PS version
    // used Start-Job).
    internal static class MemoryScanner
    {
        public static void Start()
        {
            if (!Config.EnableMemoryScanning)
            {
                Logger.Log("Memory scanning is disabled in configuration");
                return;
            }

            Logger.Log("Starting optimized memory scanner (interval: " +
                Config.MemoryScanIntervalSec + "s, max size: " +
                Config.MemoryScanMaxSizeMB + "MB)");

            PidRegistry.RegisterSelf();

            var t = new Thread(ScanLoop) { IsBackground = true, Name = "MemoryScanner" };
            t.Start();
        }

        private static void ScanLoop()
        {
            long maxBytes = (long)Config.MemoryScanMaxSizeMB * 1024 * 1024;

            while (true)
            {
                Thread.Sleep(Config.MemoryScanIntervalSec * 1000);

                HashSet<int> ownPids = PidRegistry.GetOwnPidSet();

                foreach (Process process in Process.GetProcesses())
                {
                    try
                    {
                        if (process.WorkingSet64 >= maxBytes) { process.Dispose(); continue; }
                        if (Config.ProtectedProcesses.Contains(process.ProcessName)) { process.Dispose(); continue; }
                        if (ownPids.Contains(process.Id)) { process.Dispose(); continue; }
                        if (SentinelCoexistence.IsProtectedProcess(process)) { process.Dispose(); continue; }

                        bool suspicious = false;
                        var reasons = new List<string>();

                        string path = null;
                        try { path = process.MainModule != null ? process.MainModule.FileName : null; }
                        catch { }
                        if (string.IsNullOrEmpty(path))
                        {
                            suspicious = true;
                            reasons.Add("NoPath");
                        }

                        try
                        {
                            foreach (ProcessModule m in process.Modules)
                            {
                                if (string.IsNullOrEmpty(m.FileName) || string.IsNullOrEmpty(m.ModuleName))
                                {
                                    suspicious = true;
                                    reasons.Add("EmptyModule");
                                    break;
                                }
                            }
                        }
                        catch { }

                        try
                        {
                            foreach (ProcessModule m in process.Modules)
                            {
                                foreach (string evil in Config.EvilStrings)
                                {
                                    bool nameHit = (m.ModuleName ?? "").IndexOf(evil, StringComparison.OrdinalIgnoreCase) >= 0;
                                    bool fileHit = !string.IsNullOrEmpty(m.FileName) &&
                                        m.FileName.IndexOf(evil, StringComparison.OrdinalIgnoreCase) >= 0;
                                    if (nameHit || fileHit)
                                    {
                                        suspicious = true;
                                        reasons.Add("EvilString(" + evil + ")");
                                        break;
                                    }
                                }
                                if (suspicious) break;
                            }
                        }
                        catch { }

                        if (suspicious)
                        {
                            string reasonString = string.Join("; ", reasons.ToArray());
                            string logEntry = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
                                " | MEMORY HIT [" + reasonString + "] -> " + process.ProcessName +
                                " (PID: " + process.Id + ") Path: '" + (path ?? "") + "' WS: " +
                                Math.Round(process.WorkingSet64 / 1024.0 / 1024.0, 2) + "MB";
                            try { File.AppendAllText(Config.MemoryHitsLog, logEntry + Environment.NewLine, new UTF8Encoding(false)); }
                            catch { }
                            try { SentinelCoexistence.KillUnlessSentinel(process); } catch { }
                        }
                    }
                    catch { }
                    finally { try { process.Dispose(); } catch { } }
                }

                // Deterministic cleanup after each pass.
                Logger.ClearProcessMemory();
            }
        }
    }
}
