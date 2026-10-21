using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace NanoAV
{
    // Scored C2 detection, beacon tracking, reverse-shell killer and firewall
    // auto-block. Direct port of the C2 section of the PS1.
    internal static class C2Engine
    {
        // Beacon tracking: per "PID|RemoteIP" key, timestamps of established conns.
        private static readonly Dictionary<string, List<DateTime>> BeaconHistory =
            new Dictionary<string, List<DateTime>>();
        // Remote IPs already firewall-blocked this run.
        private static readonly HashSet<string> BlockedC2Ips = new HashSet<string>();

        private static readonly Regex Ipv4Regex = new Regex(@"^\d{1,3}(\.\d{1,3}){3}$");

        public static bool IsAdmin;

        public static bool TestPrivateOrLocalAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address)) return true;
            if (address == "0.0.0.0" || address == "::" || address == "::1") return true;
            string[] privatePrefixes =
            {
                "127.", "10.", "192.168.", "169.254.",
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.", "fe80:", "fc", "fd"
            };
            string lower = address.ToLowerInvariant();
            foreach (string p in privatePrefixes)
                if (lower.StartsWith(p)) return true;
            return false;
        }

        public static bool TestReverseShellCommandLine(string commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine)) return false;
            foreach (string pattern in Config.ReverseShellPatterns)
                if (Regex.IsMatch(commandLine, pattern, RegexOptions.IgnoreCase)) return true;
            return false;
        }

        public static void BlockRemoteC2Ip(string remoteAddress, string reason)
        {
            if (!Config.EnableFirewallAutoBlock) return;
            if (TestPrivateOrLocalAddress(remoteAddress)) return;
            if (BlockedC2Ips.Contains(remoteAddress)) return;
            if (!IsAdmin)
            {
                Logger.Log("C2 block skipped (needs admin): " + remoteAddress);
                return;
            }
            try
            {
                string ruleName = "NanoAVLite_Block_C2_" + Regex.Replace(remoteAddress, "[:.]", "_");
                // netsh advfirewall replaces New-NetFirewallRule.
                ProcessHelper.Run("netsh",
                    "advfirewall firewall add rule name=\"" + ruleName +
                    "\" dir=out action=block remoteip=" + remoteAddress + " protocol=any");
                Logger.Log("FIREWALL: Blocked C2 IP " + remoteAddress + " [" + reason + "]");
                BlockedC2Ips.Add(remoteAddress);
            }
            catch (Exception ex)
            {
                Logger.Log("Firewall block failed for " + remoteAddress + " : " + ex.Message);
            }
        }

        public static void StopC2Process(int processId, string processName, string reason, HashSet<int> ownPids)
        {
            if (ownPids != null && ownPids.Contains(processId))
            {
                Logger.Log("C2 kill skipped - own NanoAV process (PID: " + processId + ")");
                return;
            }
            if (Config.ProtectedProcesses.Contains(processName))
            {
                Logger.Log("C2 kill skipped - protected process " + processName +
                    " (PID: " + processId + ") [" + reason + "]");
                return;
            }
            try
            {
                using (var target = Process.GetProcessById(processId))
                    SentinelCoexistence.KillUnlessSentinel(target);
                Logger.Log("KILLED C2/reverse-shell process " + processName +
                    " (PID: " + processId + ") [" + reason + "]");
                Alerts.Send("CRITICAL", "C2/reverse-shell process terminated",
                    processName + " PID:" + processId + " - " + reason);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to kill C2 process " + processName +
                    " (PID: " + processId + "): " + ex.Message);
            }
        }

        private sealed class BeaconVerdict
        {
            public double AverageInterval;
            public double Jitter;
            public int Samples;
        }

        private static BeaconVerdict UpdateBeaconHistory(int processId, string remoteAddress)
        {
            string key = processId + "|" + remoteAddress;
            List<DateTime> list;
            if (!BeaconHistory.TryGetValue(key, out list))
            {
                list = new List<DateTime>();
                BeaconHistory[key] = list;
            }
            list.Add(DateTime.Now);
            while (list.Count > 50) list.RemoveAt(0);

            if (list.Count < Config.BeaconMinSamples) return null;

            var intervals = new List<double>();
            for (int i = 1; i < list.Count; i++)
                intervals.Add((list[i] - list[i - 1]).TotalSeconds);
            if (intervals.Count < 2) return null;

            double sum = 0;
            foreach (double v in intervals) sum += v;
            double avg = sum / intervals.Count;
            if (avg < Config.BeaconMinIntervalSec || avg > Config.BeaconMaxIntervalSec) return null;

            double varSum = 0;
            foreach (double v in intervals) varSum += Math.Pow(v - avg, 2);
            double stdDev = Math.Sqrt(varSum / intervals.Count);

            if (stdDev < avg * Config.BeaconMaxJitterRatio)
                return new BeaconVerdict
                {
                    AverageInterval = Math.Round(avg, 1),
                    Jitter = Math.Round(stdDev, 1),
                    Samples = list.Count
                };
            return null;
        }

        private sealed class ScoreResult
        {
            public int Score;
            public List<string> Reasons = new List<string>();
        }

        private static ScoreResult GetConnectionScore(Native.TcpConnection conn, Process proc)
        {
            var r = new ScoreResult();
            int remotePort = conn.RemotePort;
            string remoteAddr = conn.RemoteAddress;

            if (Config.C2SuspiciousPorts.ContainsKey(remotePort))
            {
                r.Score += Config.C2SuspiciousPorts[remotePort];
                r.Reasons.Add("Backdoor/C2 port " + remotePort);
            }

            foreach (string prefix in Config.C2MaliciousRangePrefixes)
            {
                if (remoteAddr.StartsWith(prefix))
                {
                    r.Score += 25;
                    r.Reasons.Add("Known-bad IP range " + prefix);
                    break;
                }
            }

            if (proc != null)
            {
                string pname = proc.ProcessName.ToLowerInvariant();

                if (Array.IndexOf(Config.C2SuspiciousProcesses, pname) >= 0)
                {
                    r.Score += 25;
                    r.Reasons.Add("Interpreter/LOLBin with outbound socket (" + pname + ")");
                }

                string procPath = null;
                try { procPath = proc.MainModule != null ? proc.MainModule.FileName : null; }
                catch { }
                if (!string.IsNullOrEmpty(procPath) &&
                    !Regex.IsMatch(procPath, @"^C:\\(Windows|Program Files|Program Files \(x86\))",
                        RegexOptions.IgnoreCase))
                {
                    r.Score += 15;
                    r.Reasons.Add("Non-standard process path");
                }

                if (Regex.IsMatch(pname, @"^(svchost|lsass|winlogon|services|csrss|smss|wininit)$"))
                {
                    int[] standard = { 80, 443, 123, 53, 88, 135, 389, 445, 636 };
                    if (Array.IndexOf(standard, remotePort) < 0)
                    {
                        r.Score += 30;
                        r.Reasons.Add("System process (" + pname + ") outbound to unusual port " + remotePort);
                    }
                }

                string cmd = Wmi.GetCommandLine(proc.Id);
                if (TestReverseShellCommandLine(cmd))
                {
                    r.Score += 45;
                    r.Reasons.Add("Reverse-shell command line");
                }
            }

            if (Ipv4Regex.IsMatch(remoteAddr))
            {
                try
                {
                    string hostName = System.Net.Dns.GetHostEntry(remoteAddr).HostName;
                    if (!string.IsNullOrEmpty(hostName))
                    {
                        string hl = hostName.ToLowerInvariant();
                        foreach (string tld in Config.C2SuspiciousTLDs)
                        {
                            if (hl.EndsWith(tld) || hl.Contains(tld))
                            {
                                r.Score += 20;
                                r.Reasons.Add("Suspicious hostname TLD (" + hostName + ")");
                                break;
                            }
                        }
                    }
                }
                catch { }
            }

            return r;
        }

        public static void InvokeC2Detection()
        {
            if (!Config.EnableC2Detection) return;

            HashSet<int> ownPids = PidRegistry.GetOwnPidSet();
            var seenKeys = new HashSet<string>();

            List<Native.TcpConnection> connections;
            try
            {
                connections = new List<Native.TcpConnection>();
                foreach (var c in Native.GetTcpConnections())
                {
                    if (c.State != Native.STATE_ESTABLISHED) continue;
                    if (TestPrivateOrLocalAddress(c.RemoteAddress)) continue;
                    connections.Add(c);
                }
            }
            catch { return; }

            var procIpMap = new Dictionary<int, HashSet<string>>();

            foreach (var conn in connections)
            {
                int procId = conn.OwningProcess;
                if (procId <= 0 || ownPids.Contains(procId)) continue;

                Process proc = null;
                try { proc = Process.GetProcessById(procId); } catch { }
                string pname = proc != null ? proc.ProcessName : "Unknown";

                if (!procIpMap.ContainsKey(procId))
                    procIpMap[procId] = new HashSet<string>();
                procIpMap[procId].Add(conn.RemoteAddress);

                ScoreResult result = GetConnectionScore(conn, proc);
                int score = result.Score;
                var reasons = result.Reasons;

                string bkey = procId + "|" + conn.RemoteAddress;
                if (Config.EnableBeaconDetection && !seenKeys.Contains(bkey))
                {
                    seenKeys.Add(bkey);
                    BeaconVerdict beacon = UpdateBeaconHistory(procId, conn.RemoteAddress);
                    if (beacon != null)
                    {
                        score += 30;
                        reasons.Add("Beacon cadence ~" + beacon.AverageInterval + "s (jitter " +
                            beacon.Jitter + "s, n=" + beacon.Samples + ")");
                    }
                }

                if (score <= 0) { if (proc != null) proc.Dispose(); continue; }

                string target = conn.RemoteAddress + ":" + conn.RemotePort;
                string reasonStr = string.Join("; ", reasons.ToArray());

                if (score >= Config.FirewallBlockThreshold)
                {
                    Logger.Log("C2 SUSPECT (score " + score + "): " + pname + " (PID " + procId +
                        ") -> " + target + " | " + reasonStr);
                    Alerts.Send("HIGH", "Suspicious C2 connection (score " + score + ")",
                        pname + " -> " + target + " | " + reasonStr);
                    BlockRemoteC2Ip(conn.RemoteAddress, "score " + score);
                }

                if (score >= Config.KillScoreThreshold)
                    StopC2Process(procId, pname, "C2 score " + score + " -> " + target, ownPids);

                if (proc != null) proc.Dispose();
            }

            // IP-rotation detection.
            foreach (var entry in procIpMap)
            {
                if (entry.Value.Count >= Config.IpRotationThreshold)
                {
                    int procId = entry.Key;
                    if (ownPids.Contains(procId)) continue;
                    string pname = "Unknown";
                    try { using (var p = Process.GetProcessById(procId)) pname = p.ProcessName; } catch { }
                    Logger.Log("C2 IP-ROTATION: " + pname + " (PID " + procId + ") -> " +
                        entry.Value.Count + " unique remote IPs");
                    Alerts.Send("HIGH", "C2 IP rotation detected",
                        pname + " PID:" + procId + " -> " + entry.Value.Count + " IPs");
                    StopC2Process(procId, pname, "IP rotation (" + entry.Value.Count + " IPs)", ownPids);
                }
            }

            // Prune beacon-history keys whose process no longer exists.
            var deadKeys = new List<string>();
            foreach (string k in BeaconHistory.Keys)
            {
                int kpid;
                if (int.TryParse(k.Split('|')[0], out kpid))
                {
                    bool alive;
                    try { Process.GetProcessById(kpid); alive = true; } catch { alive = false; }
                    if (!alive) deadKeys.Add(k);
                }
            }
            foreach (string k in deadKeys) BeaconHistory.Remove(k);
        }

        public static void InvokeReverseShellKiller()
        {
            if (!Config.EnableReverseShellKill) return;

            HashSet<int> ownPids = PidRegistry.GetOwnPidSet();
            List<Wmi.ProcInfo> procInfos;
            try { procInfos = Wmi.GetProcessesWithCommandLine(); }
            catch { return; }

            foreach (var pi in procInfos)
            {
                int procId = pi.ProcessId;
                if (procId <= 0 || ownPids.Contains(procId)) continue;
                if (!TestReverseShellCommandLine(pi.CommandLine)) continue;

                string pname = Regex.Replace(pi.Name ?? "", @"\.exe$", "", RegexOptions.IgnoreCase);
                if (Config.ProtectedProcesses.Contains(pname))
                {
                    Logger.Log("Reverse-shell signature on protected process " + pname +
                        " (PID " + procId + ") - logging only");
                    Logger.Log("  CMD: " + pi.CommandLine);
                    continue;
                }

                Logger.Log("REVERSE SHELL DETECTED: " + pname + " (PID " + procId + ")");
                Logger.Log("  CMD: " + pi.CommandLine);
                Alerts.Send("CRITICAL", "Reverse shell command line detected", pname + " PID:" + procId);

                try
                {
                    foreach (var c in Native.GetTcpConnections())
                    {
                        if (c.OwningProcess != procId) continue;
                        if (c.State != Native.STATE_ESTABLISHED) continue;
                        if (TestPrivateOrLocalAddress(c.RemoteAddress)) continue;
                        BlockRemoteC2Ip(c.RemoteAddress, "reverse shell");
                    }
                }
                catch { }

                StopC2Process(procId, pname, "reverse-shell command line", ownPids);

                if (!string.IsNullOrEmpty(pi.ExecutablePath) && System.IO.File.Exists(pi.ExecutablePath))
                {
                    string imgLower = pi.ExecutablePath.ToLowerInvariant();
                    if (!imgLower.Contains(@"\windows\system32\") && !imgLower.Contains(@"\windows\syswow64\"))
                        FileScanner.MoveToQuarantine(pi.ExecutablePath, "Reverse-shell host image");
                }
            }
        }
    }
}
