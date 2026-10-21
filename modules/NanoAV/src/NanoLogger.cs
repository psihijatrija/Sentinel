using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace NanoAV
{
    // Write-Log + Clear-ProcessMemory equivalents.
    internal static class Logger
    {
        private static readonly object LogLock = new object();

        public static void Log(string message)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            string logLine = timestamp + " | " + message;

            lock (LogLock)
            {
                try
                {
                    File.AppendAllText(Config.LogFile, logLine + Environment.NewLine, new UTF8Encoding(false));
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[LOG ERROR] " + ex.Message);
                }
            }

            Console.WriteLine(logLine);

            try
            {
                if (File.Exists(Config.LogFile))
                {
                    long size = new FileInfo(Config.LogFile).Length;
                    if (size >= (long)Config.MaxLogSizeMB * 1024 * 1024)
                    {
                        string archive = Path.Combine(Config.BaseDirectory,
                            "NanoAV_log_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                        try { File.Move(Config.LogFile, archive); } catch { }
                    }
                }
            }
            catch { }
        }

        // GC.Collect + working-set trim, mirrors Clear-ProcessMemory.
        public static void ClearProcessMemory()
        {
            try
            {
                System.Runtime.GCSettings.LargeObjectHeapCompactionMode =
                    System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;
            }
            catch { }

            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            try
            {
                Native.EmptyWorkingSet(Process.GetCurrentProcess().Handle);
            }
            catch { }
        }
    }
}
