using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NanoAV
{
    // Behavioral heuristics: Test-ProcessHollowing, Test-CredentialAccessBehavior,
    // Test-LateralMovementBehavior, Test-C2Communication, plus the fileless /
    // persistence helpers used by the deep-scan job.
    internal static class Behavior
    {
        public static bool TestProcessHollowing(Process process)
        {
            try
            {
                string processPath;
                try { processPath = process.MainModule.FileName; }
                catch { return false; }
                if (string.IsNullOrEmpty(processPath)) return false;

                if (process.Modules.Count > 0)
                    return !string.Equals(process.Modules[0].FileName, processPath,
                        StringComparison.OrdinalIgnoreCase);
            }
            catch { }
            return false;
        }

        public static bool TestCredentialAccessBehavior(Process process)
        {
            try
            {
                string cmd = Wmi.GetCommandLine(process.Id);
                if (!string.IsNullOrEmpty(cmd) && Regex.IsMatch(cmd,
                        "mimikatz|procdump|sekurlsa|lsadump|credential|password",
                        RegexOptions.IgnoreCase))
                    return true;
            }
            catch { }

            if (Regex.IsMatch(process.ProcessName, "vaultcmd|cred", RegexOptions.IgnoreCase))
                return true;
            return false;
        }

        public static bool TestLateralMovementBehavior(Process process)
        {
            try
            {
                int external = 0;
                foreach (var c in Native.GetTcpConnections())
                {
                    if (c.OwningProcess != process.Id) continue;
                    if (IsExternal(c.RemoteAddress)) external++;
                }
                return external > 10;
            }
            catch { }
            return false;
        }

        public static bool TestC2Communication(Native.TcpConnection connection)
        {
            int[] suspiciousPorts = { 4444, 5555, 6666, 7777, 8080, 8443, 9001, 1337, 31337 };
            if (Array.IndexOf(suspiciousPorts, connection.RemotePort) < 0) return false;
            try
            {
                string hostName = System.Net.Dns.GetHostEntry(connection.RemoteAddress).HostName;
                string[] c2Domains = { "pastebin", "ddns.net", "no-ip.org", "duckdns.org", "bit.ly", "tinyurl" };
                foreach (string d in c2Domains)
                    if (hostName.IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0) return true;
            }
            catch { }
            return false;
        }

        private static bool IsExternal(string addr)
        {
            if (string.IsNullOrEmpty(addr)) return false;
            if (addr == "0.0.0.0" || addr == "::") return false;
            if (Regex.IsMatch(addr, @"^(127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)")) return false;
            if (addr == "::1" || addr.StartsWith("fe80:")) return false;
            return true;
        }

        // Find-FilelessIndicators (returns detection description strings).
        public static List<string> FindFilelessIndicators()
        {
            var detections = new List<string>();
            try
            {
                foreach (string pname in new[] { "powershell", "pwsh" })
                {
                    foreach (var p in Process.GetProcessesByName(pname))
                    {
                        try
                        {
                            if (Regex.IsMatch(p.MainWindowTitle ?? "",
                                    "encodedcommand|enc|iex|invoke-expression", RegexOptions.IgnoreCase))
                            {
                                detections.Add("FilelessPowerShell: " + p.ProcessName + " (" + p.Id + ")");
                                Logger.Log("Fileless indicator detected: PowerShell without file");
                            }
                        }
                        catch { }
                        p.Dispose();
                    }
                }
            }
            catch { }
            return detections;
        }

        // Find-PersistenceMechanisms (registry Run keys + startup folders).
        public static List<string> FindPersistenceMechanisms()
        {
            var items = new List<string>();
            var hklm = Microsoft.Win32.Registry.LocalMachine;
            var hkcu = Microsoft.Win32.Registry.CurrentUser;

            var regKeys = new[]
            {
                new { Root = hklm, Sub = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
                new { Root = hkcu, Sub = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
                new { Root = hklm, Sub = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
                new { Root = hklm, Sub = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" }
            };

            foreach (var k in regKeys)
            {
                try
                {
                    using (var key = k.Root.OpenSubKey(k.Sub))
                    {
                        if (key == null) continue;
                        foreach (string name in key.GetValueNames())
                        {
                            string val = Convert.ToString(key.GetValue(name));
                            if (val != null && Regex.IsMatch(val, @"\.(exe|dll|ps1|vbs|js|bat|cmd)$",
                                    RegexOptions.IgnoreCase))
                                items.Add("Registry: " + k.Sub + " -> " + name + " = " + val);
                        }
                    }
                }
                catch (Exception ex) { Logger.Log("Error checking persistence location " + k.Sub + " : " + ex.Message); }
            }

            var folders = new[]
            {
                @"C:\Windows\System32\Tasks",
                @"C:\Windows\Tasks",
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) +
                    @"\Microsoft\Windows\Start Menu\Programs\Startup",
                @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
            };

            foreach (string folder in folders)
            {
                try
                {
                    if (!System.IO.Directory.Exists(folder)) continue;
                    foreach (string f in System.IO.Directory.GetFiles(folder, "*",
                                 System.IO.SearchOption.AllDirectories))
                    {
                        if (Regex.IsMatch(f, @"\.(exe|dll|lnk|ps1|vbs|js|bat|cmd)$", RegexOptions.IgnoreCase))
                            items.Add("FileSystem: " + f);
                    }
                }
                catch (Exception ex) { Logger.Log("Error checking persistence location " + folder + " : " + ex.Message); }
            }

            return items;
        }
    }
}
