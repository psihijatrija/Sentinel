// NetworkIntegrity - userland coverage for UDP, ICMP, WFP net-event subscription,
// non-TCP/UDP IP protocols, and VoIP signaling/RTP-like binds.
// No kernel driver, no WinDivert, no raw sniffer, no audit-policy mutation.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Sentinel.Core
{
    /// <summary>
    /// Pure functions for UDP / ICMP / WFP / VoIP classification.
    /// InternalsVisibleTo Sentinel.Tests - no live sockets, no elevation.
    /// </summary>
    internal static class UserlandProtocolHeuristics
    {
        internal const byte ProtoIcmp = 1;
        internal const byte ProtoIgmp = 2;
        internal const byte ProtoIpv4Encap = 4;
        internal const byte ProtoTcp = 6;
        internal const byte ProtoUdp = 17;
        internal const byte ProtoIpv6Encap = 41;
        internal const byte ProtoGre = 47;
        internal const byte ProtoEsp = 50;
        internal const byte ProtoAh = 51;
        internal const byte ProtoIcmpV6 = 58;
        internal const byte ProtoOspf = 89;
        internal const byte ProtoPim = 103;
        internal const byte ProtoVrrp = 112;
        internal const byte ProtoL2tp = 115;
        internal const byte ProtoSctp = 132;

        internal static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "powershell_ise",
            "mshta", "wscript", "cscript", "rundll32", "regsvr32",
            "bash", "sh", "wmic", "bitsadmin", "certutil",
            "python", "pythonw", "py", "node", "cmd.exe",
            "msiexec", "installutil", "regasm", "regsvcs", "odbcconf",
            "cmstp", "hh", "wsl", "wslhost", "forfiles", "msdt",
            "pcalua", "presentationhost", "mavinject", "ieexec",
            "xwizard", "dnscmd", "diskshadow", "expand", "ftp", "tftp",
        };

        internal static readonly HashSet<string> KnownCommsProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "discord", "discordptb", "discordcanary", "discorddevelopment",
            "teams", "ms-teams", "msteams", "ms-teamsupdate",
            "zoom", "cpthost", "zcrashreport",
            "skype", "lync", "communicator",
            "slack", "slack-update",
            "whatsapp", "telegram", "telegram-desktop",
            "signal", "element", "wire", "viber",
            "linphone", "microsip", "3cx", "zoiper", "bria",
            "xlite", "eyebeam", "phoner", "jitsi", "ringcentral",
            "webex", "atmgr", "ciscocollabhost",
            "chrome", "msedge", "msedgewebview2", "firefox",
            "brave", "opera", "vivaldi", "chromium",
            "steam", "steamwebhelper", "steamservice",
            "epicgameslauncher", "epicwebhelper",
            "obs64", "obs32", "obs", "streamlabs obs", "streamlabs",
            "spotify",
        };

        internal static readonly HashSet<string> VpnOrIkeProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "ikeext", "rasman", "rasmans",
            "wireguard", "openvpn", "openvpn-gui", "openvpnserv",
            "tailscale", "tailscaled", "zerotier-one",
            "nordvpn", "nordvpn-service", "expressvpn", "surfshark",
            "protonvpn", "protonvpnservice",
            "warp-svc", "cloudflarewarp", "warp",
            "rasphone", "vpnui", "panmservice", "globalprotect",
        };

        internal static readonly HashSet<int> ClassicMalwareUdpPorts = new()
        {
            69,    // TFTP
            111,   // RPCBind
            161,   // SNMP
            162,   // SNMP trap
            514,   // syslog
            1434,  // SQL Slammer
            4444,  // Meterpreter
            6667,  // IRC
            12345, // NetBus
            31337, // BackOrifice
        };

        internal static readonly HashSet<int> AmbientUdpPorts = new()
        {
            53, 67, 68, 123, 137, 138, 1900, 5353, 5355, 5683,
        };

        public static string NormalizeProcessName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";
            var n = name!.Trim();
            if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                n = n.Substring(0, n.Length - 4);
            return n;
        }

        public static bool IsScriptHost(string? processName)
        {
            var n = NormalizeProcessName(processName);
            return n.Length > 0 && ScriptHosts.Contains(n);
        }

        public static bool IsKnownCommsProcess(string? processName)
        {
            var n = NormalizeProcessName(processName);
            return n.Length > 0 && KnownCommsProcesses.Contains(n);
        }

        public static bool IsVpnOrIkeProcess(string? processName)
        {
            var n = NormalizeProcessName(processName);
            return n.Length > 0 && VpnOrIkeProcesses.Contains(n);
        }

        /// <summary>
        /// Install trees for the real comms/browser/Steam/OBS apps. Name-only
        /// is not identity - discord.exe in Temp is the attack.
        /// </summary>
        internal static readonly string[] CommsInstallPathFragments =
        {
            @"\appdata\local\discord\",
            @"\appdata\local\discordptb\",
            @"\appdata\local\discordcanary\",
            @"\appdata\local\discorddevelopment\",
            @"\appdata\roaming\discord\",
            @"\program files\google\chrome\",
            @"\program files (x86)\google\chrome\",
            @"\appdata\local\google\chrome\",
            @"\program files\mozilla firefox\",
            @"\program files (x86)\mozilla firefox\",
            @"\appdata\local\microsoft\edge\",
            @"\program files (x86)\microsoft\edge\",
            @"\program files\microsoft\edge\",
            @"\appdata\local\bravesoftware\",
            @"\program files\brave\",
            @"\appdata\local\vivaldi\",
            @"\appdata\local\opera software\",
            @"\program files\steam\",
            @"\program files (x86)\steam\",
            @"\steamapps\common\",
            @"\appdata\roaming\telegram desktop\",
            @"\appdata\roaming\zoom\",
            @"\program files\zoom\",
            @"\appdata\roaming\slack\",
            @"\appdata\local\slack\",
            @"\appdata\local\microsoft\teams\",
            @"\appdata\local\microsoft\teamsmeetingaddin\",
            @"\windowsapps\",
            @"\program files\obs-studio\",
            @"\appdata\local\programs\obs-studio\",
            @"\appdata\roaming\spotify\",
            @"\program files\windowsapps\",
            @"\appdata\local\programs\signal\",
            @"\appdata\roaming\whatsapp\",
        };

        internal static readonly string[] VpnInstallPathFragments =
        {
            @"\program files\tailscale\",
            @"\program files\wireguard\",
            @"\program files\openvpn\",
            @"\program files\nordvpn\",
            @"\program files\expressvpn\",
            @"\program files\surfshark\",
            @"\program files\protonvpn\",
            @"\program files\cloudflare\",
            @"\program files\zerotier\",
            @"\program files\palo alto networks\",
            @"\globalprotect\",
        };

        internal static readonly HashSet<string> WindowsVpnServiceNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost", "ikeext", "rasman", "rasmans", "rasphone",
        };

        /// <summary>
        /// Real Discord/Chrome/Steam - name AND install path (or live Authenticode).
        /// Missing path, Temp/Downloads, or unsigned plant in a stolen folder: not a civilian.
        /// </summary>
        public static bool IsKnownCommsIdentity(string? processName, string? imagePath)
            => IsVerifiedInstallIdentity(processName, imagePath, KnownCommsProcesses, CommsInstallPathFragments);

        /// <summary>
        /// Real Tailscale/WireGuard/IKE - not tailscale.exe in Temp, not fake svchost.
        /// </summary>
        public static bool IsVpnOrIkeIdentity(string? processName, string? imagePath)
        {
            var n = NormalizeProcessName(processName);
            if (n.Length == 0 || !VpnOrIkeProcesses.Contains(n))
                return false;
            if (WindowsVpnServiceNames.Contains(n))
                return SecurityValidation.IsWindowsSystemImage(imagePath);
            return IsVerifiedInstallIdentity(processName, imagePath, VpnOrIkeProcesses, VpnInstallPathFragments);
        }

        public static bool IsVerifiedInstallIdentity(
            string? processName,
            string? imagePath,
            HashSet<string> names,
            string[] pathFragments)
        {
            var n = NormalizeProcessName(processName);
            if (n.Length == 0 || !names.Contains(n))
                return false;
            if (string.IsNullOrEmpty(imagePath))
                return false;
            if (IsSuspiciousPath(imagePath))
                return false;

            var lower = imagePath!.ToLowerInvariant();
            bool pathOk = false;
            foreach (var f in pathFragments)
            {
                if (lower.Contains(f))
                {
                    pathOk = true;
                    break;
                }
            }

            bool exists = false;
            try { exists = System.IO.File.Exists(imagePath); } catch { }

            if (!pathOk)
            {
                if (!exists) return false;
                try { return SecurityValidation.VerifyAuthenticodeSignature(imagePath); }
                catch { return false; }
            }

            // Path looks civilian. If the file is on disk, it must still be signed -
            // unsigned plant in AppData\Local\Discord is the costume.
            if (!exists)
                return true;
            try { return SecurityValidation.VerifyAuthenticodeSignature(imagePath); }
            catch { return false; }
        }

        public static bool IsSuspiciousPath(string? path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            var lower = path!.ToLowerInvariant();
            return lower.Contains(@"\temp\") ||
                   lower.Contains(@"\downloads\") ||
                   lower.Contains(@"\appdata\local\temp");
        }

        public static bool IsSipPort(int port) =>
            port == 5060 || port == 5061 || port == 5062 || port == 5070;

        public static bool IsStunTurnPort(int port) =>
            port == 3478 || port == 3479 || port == 3480 || port == 3481 ||
            port == 5349 || port == 19302 || port == 19305 ||
            (port >= 3478 && port <= 3497);

        public static bool IsH323Port(int port) => port == 1719 || port == 1720;

        public static bool IsIaxPort(int port) => port == 4569;

        public static bool IsMgcpPort(int port) => port == 2427 || port == 2727;

        public static bool IsVoipSignalingPort(int port) =>
            IsSipPort(port) || IsStunTurnPort(port) || IsH323Port(port) ||
            IsIaxPort(port) || IsMgcpPort(port);

        /// <summary>
        /// Even ports in the classic RTP even/RTCP-odd band. Too broad to alert on
        /// alone - combine with process identity.
        /// </summary>
        public static bool IsClassicRtpPort(int port) =>
            port >= 16384 && port <= 32767 && (port % 2 == 0);

        public static string VoipPortLabel(int port)
        {
            if (IsSipPort(port)) return "SIP";
            if (IsStunTurnPort(port)) return "STUN/TURN";
            if (IsH323Port(port)) return "H.323";
            if (IsIaxPort(port)) return "IAX";
            if (IsMgcpPort(port)) return "MGCP";
            if (IsClassicRtpPort(port)) return "RTP-like";
            return "VoIP";
        }

        public static string IpProtocolName(byte proto) => proto switch
        {
            0 => "HOPOPT",
            ProtoIcmp => "ICMP",
            ProtoIgmp => "IGMP",
            ProtoIpv4Encap => "IPv4-encap",
            ProtoTcp => "TCP",
            ProtoUdp => "UDP",
            ProtoIpv6Encap => "IPv6-encap",
            ProtoGre => "GRE",
            ProtoEsp => "ESP",
            ProtoAh => "AH",
            ProtoIcmpV6 => "ICMPv6",
            ProtoOspf => "OSPF",
            ProtoPim => "PIM",
            ProtoVrrp => "VRRP",
            ProtoL2tp => "L2TP",
            ProtoSctp => "SCTP",
            _ => $"IP-proto-{proto}",
        };

        /// <summary>
        /// Protocols NetworkMonitor (TCP) and UdpFlowMonitor (UDP) do not cover.
        /// ICMP is covered by IcmpAnomalyMonitor but WFP still attributes a PID.
        /// </summary>
        public static bool IsNonTcpUdpProtocol(byte proto) =>
            proto != ProtoTcp && proto != ProtoUdp && proto != 0;

        public static bool IsUnusualIpProtocol(byte proto) =>
            proto == ProtoGre || proto == ProtoEsp || proto == ProtoAh ||
            proto == ProtoIpv4Encap || proto == ProtoIpv6Encap ||
            proto == ProtoSctp || proto == ProtoL2tp || proto == ProtoOspf ||
            proto == ProtoPim || proto == ProtoVrrp || proto == ProtoIgmp;

        public static bool IsAmbientUdp(int port, string? processName)
        {
            if (!AmbientUdpPorts.Contains(port)) return false;
            var n = NormalizeProcessName(processName);
            return n.Length == 0 ||
                   n.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                   n.Equals("dashost", StringComparison.OrdinalIgnoreCase) ||
                   n.Equals("system", StringComparison.OrdinalIgnoreCase) ||
                   n.Equals("dnscache", StringComparison.OrdinalIgnoreCase);
        }

        public static bool ShouldSkipWorkSurface(string? processName, string? imagePath)
        {
            if (IsKnownCommsIdentity(processName, imagePath)) return true;
            if (IsVpnOrIkeIdentity(processName, imagePath)) return true;
            if (AlwaysOnPolicies.IsProtectedGamePath(imagePath)) return true;
            if (InstallerHeuristics.IsDirectXOrRuntimeRedist(processName, imagePath)) return true;
            if (InstallerHeuristics.IsBenignPortableWorkContext(processName, imagePath)) return true;
            return false;
        }

        public enum UdpVerdictKind
        {
            None,
            LolbinDatagram,
            SuspiciousPath,
            ClassicMalwarePort,
            SocketExplosion,
        }

        public static UdpVerdictKind ClassifyUdpBind(
            string? processName, string? imagePath, int localPort, int socketCountForPid)
        {
            if (ShouldSkipWorkSurface(processName, imagePath))
                return UdpVerdictKind.None;
            if (IsAmbientUdp(localPort, processName))
                return UdpVerdictKind.None;

            if (ClassicMalwareUdpPorts.Contains(localPort))
                return UdpVerdictKind.ClassicMalwarePort;

            if (IsScriptHost(processName) && localPort != 53)
                return UdpVerdictKind.LolbinDatagram;

            if (IsSuspiciousPath(imagePath) && localPort != 53)
                return UdpVerdictKind.SuspiciousPath;

            if (socketCountForPid >= 64 && !IsVpnOrIkeProcess(processName))
                return UdpVerdictKind.SocketExplosion;

            return UdpVerdictKind.None;
        }

        public enum IcmpVerdictKind
        {
            None,
            EchoFlood,
            RedirectInbound,
            UnreachableStorm,
        }

        public static IcmpVerdictKind ClassifyIcmpDelta(
            uint echoPerSec, uint inboundRedirects, uint unreachPerSec, bool baselineReady)
        {
            if (!baselineReady) return IcmpVerdictKind.None;
            if (inboundRedirects > 0) return IcmpVerdictKind.RedirectInbound;
            if (echoPerSec >= 50) return IcmpVerdictKind.EchoFlood;
            if (unreachPerSec >= 80) return IcmpVerdictKind.UnreachableStorm;
            return IcmpVerdictKind.None;
        }

        public enum WfpVerdictKind
        {
            None,
            UnusualIpProtocol,
            IPsecKernelDrop,
            ClassifyDrop,
        }

        public const int WfpTypeIkeMmFailure = 0;
        public const int WfpTypeIkeQmFailure = 1;
        public const int WfpTypeIkeEmFailure = 2;
        public const int WfpTypeClassifyDrop = 3;
        public const int WfpTypeIpsecKernelDrop = 4;
        public const int WfpTypeIpsecDospDrop = 5;
        public const int WfpTypeClassifyAllow = 6;
        public const int WfpTypeCapabilityDrop = 7;

        public static WfpVerdictKind ClassifyWfpEvent(
            byte ipProtocol, int eventType, string? processName, string? imagePath)
        {
            if (ShouldSkipWorkSurface(processName, imagePath))
                return WfpVerdictKind.None;

            if (eventType == WfpTypeIpsecKernelDrop || eventType == WfpTypeIpsecDospDrop)
                return WfpVerdictKind.IPsecKernelDrop;

            if (IsUnusualIpProtocol(ipProtocol))
            {
                if ((ipProtocol == ProtoEsp || ipProtocol == ProtoAh || ipProtocol == ProtoGre) &&
                    IsVpnOrIkeIdentity(processName, imagePath))
                    return WfpVerdictKind.None;
                return WfpVerdictKind.UnusualIpProtocol;
            }

            if (eventType == WfpTypeClassifyDrop || eventType == WfpTypeCapabilityDrop)
                return WfpVerdictKind.ClassifyDrop;

            return WfpVerdictKind.None;
        }

        public enum VoipVerdictKind
        {
            None,
            SipUnexpected,
            StunUnexpected,
            HiddenRtpBinds,
        }

        public static VoipVerdictKind ClassifyVoip(
            string? processName, string? imagePath, int port, int rtpLikeBindCount, bool signalingPort)
        {
            if (ShouldSkipWorkSurface(processName, imagePath))
                return VoipVerdictKind.None;

            var n = NormalizeProcessName(processName);
            if (n.Equals("svchost", StringComparison.OrdinalIgnoreCase) &&
                SecurityValidation.IsWindowsSystemImage(imagePath))
                return VoipVerdictKind.None;

            if (signalingPort && IsSipPort(port))
                return VoipVerdictKind.SipUnexpected;
            if (signalingPort && (IsStunTurnPort(port) || IsH323Port(port) || IsIaxPort(port) || IsMgcpPort(port)))
                return VoipVerdictKind.StunUnexpected;

            if (!signalingPort && rtpLikeBindCount >= 2 &&
                (IsScriptHost(processName) || IsSuspiciousPath(imagePath)))
                return VoipVerdictKind.HiddenRtpBinds;

            return VoipVerdictKind.None;
        }

        public static double ConfidenceFor(UdpVerdictKind k) => k switch
        {
            UdpVerdictKind.LolbinDatagram => 0.62,
            UdpVerdictKind.ClassicMalwarePort => 0.58,
            UdpVerdictKind.SuspiciousPath => 0.42,
            UdpVerdictKind.SocketExplosion => 0.50,
            _ => 0,
        };

        public static double ConfidenceFor(IcmpVerdictKind k) => k switch
        {
            IcmpVerdictKind.RedirectInbound => 0.78,
            IcmpVerdictKind.EchoFlood => 0.55,
            IcmpVerdictKind.UnreachableStorm => 0.52,
            _ => 0,
        };

        public static double ConfidenceFor(WfpVerdictKind k) => k switch
        {
            WfpVerdictKind.UnusualIpProtocol => 0.70,
            WfpVerdictKind.IPsecKernelDrop => 0.60,
            WfpVerdictKind.ClassifyDrop => 0.40,
            _ => 0,
        };

        public static double ConfidenceFor(VoipVerdictKind k, bool scriptHost) => k switch
        {
            VoipVerdictKind.SipUnexpected => scriptHost ? 0.78 : 0.62,
            VoipVerdictKind.StunUnexpected => scriptHost ? 0.70 : 0.55,
            VoipVerdictKind.HiddenRtpBinds => scriptHost ? 0.72 : 0.58,
            _ => 0,
        };

        /// <summary>
        /// Names used by userspace WireGuard / magicsock / DERP overlays.
        /// Enrichment only - never a President's-law kill. Official
        /// <c>tailscale</c>/<c>wireguard</c> NICs are skipped via <see cref="IsVpnOrIkeProcess"/>.
        /// </summary>
        internal static readonly HashSet<string> CovertMeshProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "tailcat", "tailcat-web", "tailcat-webdist",
            "derper", "magicsock",
            "wireproxy", "onetun", "boringtun", "wireguard-go",
            "innernet", "netmaker", "netclient",
            "sliver", "sliver-client", "sliver-server",
            "headscale",
        };

        public static bool LooksLikeCovertMeshName(string? processName)
        {
            var n = NormalizeProcessName(processName);
            if (n.Length == 0) return false;
            if (CovertMeshProcessNames.Contains(n)) return true;
            foreach (var stem in CovertMeshProcessNames)
            {
                if (stem.Length >= 6 && n.IndexOf(stem, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }
            return false;
        }

        /// <summary>
        /// DERP / tailcat / magicsock bootstrap hosts. Official Tailscale
        /// clients still talk here - those PIDs are skipped separately.
        /// </summary>
        public static bool IsCovertMeshDomain(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return false;
            var h = host!.Trim().TrimEnd('.').ToLowerInvariant();
            if (h.StartsWith("http://", StringComparison.Ordinal) ||
                h.StartsWith("https://", StringComparison.Ordinal))
            {
                if (Uri.TryCreate(h, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
                    h = uri.Host;
            }

            if (h == "tailcat.dev" || h.EndsWith(".tailcat.dev", StringComparison.Ordinal))
                return true;
            if (h == "derp.tailscale.com" || h.EndsWith(".derp.tailscale.com", StringComparison.Ordinal))
                return true;
            if (h.StartsWith("derp", StringComparison.Ordinal) &&
                (h.EndsWith(".tailscale.com", StringComparison.Ordinal) ||
                 h.EndsWith(".tailscale.io", StringComparison.Ordinal)))
                return true;
            if (h.IndexOf("derpmap", StringComparison.Ordinal) >= 0)
                return true;
            return false;
        }

        public enum CovertMeshKind
        {
            None,
            NamedTool,
            DerpRelay,
            StunHolePunch,
            UserWritableOverlay,
        }

        /// <summary>
        /// Userspace mesh C2 shape (tailcat and anything like it):
        /// UDP overlay + (DERP HTTPS / STUN hole-punch / user-writable path),
        /// and not an installed VPN NIC, browser, game, or comms app.
        /// </summary>
        public static CovertMeshKind ClassifyCovertMesh(
            string? processName,
            string? imagePath,
            int nonAmbientUdpBinds,
            bool hasStunPort,
            bool hasHttps,
            bool meshDnsRecently)
        {
            if (ShouldSkipWorkSurface(processName, imagePath))
                return CovertMeshKind.None;
            if (BulkTransferNoise.IsBulkTransferProcessName(processName))
                return CovertMeshKind.None;

            var n = NormalizeProcessName(processName);
            if ((n.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                 n.Equals("system", StringComparison.OrdinalIgnoreCase) ||
                 n.Equals("lsass", StringComparison.OrdinalIgnoreCase)) &&
                SecurityValidation.IsWindowsSystemImage(imagePath))
                return CovertMeshKind.None;

            if (LooksLikeCovertMeshName(processName))
                return CovertMeshKind.NamedTool;

            if (nonAmbientUdpBinds <= 0)
                return CovertMeshKind.None;

            // Host-wide DERP DNS is not enough - require this PID also has HTTPS (DERP)
            // or is already in a staging path / script host.
            if (meshDnsRecently && (hasHttps || IsSuspiciousPath(imagePath) || IsScriptHost(processName)))
                return CovertMeshKind.DerpRelay;

            if (hasStunPort && (hasHttps || IsSuspiciousPath(imagePath) || IsScriptHost(processName)))
                return CovertMeshKind.StunHolePunch;

            if (IsSuspiciousPath(imagePath) && hasHttps)
                return CovertMeshKind.UserWritableOverlay;

            if (IsScriptHost(processName) && hasHttps)
                return CovertMeshKind.UserWritableOverlay;

            return CovertMeshKind.None;
        }

        public static double ConfidenceFor(CovertMeshKind k) => k switch
        {
            CovertMeshKind.NamedTool => 0.90,
            CovertMeshKind.DerpRelay => 0.88,
            CovertMeshKind.UserWritableOverlay => 0.88,
            CovertMeshKind.StunHolePunch => 0.86,
            _ => 0,
        };

        /// <summary>
        /// Purpose-built HTTP callback sinks. A browser visiting these is skipped
        /// via <see cref="ShouldSkipWorkSurface"/>; a script host is a stealer.
        /// </summary>
        internal static readonly string[] DedicatedWebhookSinkHosts =
        {
            "webhook.site", "pipedream.net", "requestbin.com", "requestbin.net",
            "hookbin.com", "beeceptor.com", "mockbin.org", "interact.sh",
            "oast.fun", "oastify.com", "oast.pro", "canarytokens.com",
            "canarytokens.org", "webhookrelay.com",
        };

        /// <summary>
        /// Comms platforms stealers abuse as anonymous POST sinks.
        /// Official Discord/Telegram/Slack apps are skipped by name.
        /// </summary>
        internal static readonly string[] CommsExfilHosts =
        {
            "discord.com", "discordapp.com", "api.telegram.org", "hooks.slack.com",
        };

        /// <summary>
        /// Path / URL fragments visible in command lines and PowerShell 4104.
        /// HTTPS on the wire never shows these without TLS intercept.
        /// </summary>
        internal static readonly string[] WebhookUrlFragments =
        {
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "api.telegram.org/bot",
            "hooks.slack.com/",
            "webhook.site/",
            "telegram-bot",
        };

        public static string NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return "";
            var h = host!.Trim().TrimEnd('.').ToLowerInvariant();
            if (h.StartsWith("http://", StringComparison.Ordinal) ||
                h.StartsWith("https://", StringComparison.Ordinal))
            {
                if (Uri.TryCreate(h, UriKind.Absolute, out var uri) && !string.IsNullOrEmpty(uri.Host))
                    h = uri.Host;
            }
            if (h.StartsWith("www.", StringComparison.Ordinal))
                h = h.Substring(4);
            return h;
        }

        public static bool HostMatches(string host, string suffix)
        {
            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(suffix)) return false;
            return host.Equals(suffix, StringComparison.Ordinal) ||
                   host.EndsWith("." + suffix, StringComparison.Ordinal);
        }

        public static bool IsDedicatedWebhookSink(string? host)
        {
            var h = NormalizeHost(host);
            if (h.Length == 0) return false;
            foreach (var s in DedicatedWebhookSinkHosts)
            {
                if (HostMatches(h, s)) return true;
            }
            return false;
        }

        public static bool IsCommsExfilHost(string? host)
        {
            var h = NormalizeHost(host);
            if (h.Length == 0) return false;
            foreach (var s in CommsExfilHosts)
            {
                if (h.Equals(s, StringComparison.Ordinal)) return true;
            }
            return false;
        }

        public static bool ContainsWebhookUrl(string? text)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            var t = text!.ToLowerInvariant();
            foreach (var f in WebhookUrlFragments)
            {
                if (t.IndexOf(f, StringComparison.Ordinal) >= 0)
                    return true;
            }
            foreach (var s in DedicatedWebhookSinkHosts)
            {
                if (t.IndexOf(s, StringComparison.Ordinal) >= 0)
                    return true;
            }
            return false;
        }

        public enum WebhookKind
        {
            None,
            DedicatedSink,
            CommsPlatformAbuse,
            UrlInContent,
        }

        /// <summary>
        /// Stealers POST to Discord/Telegram/Slack webhooks or disposable
        /// callback hosts. No TLS intercept - host identity + process context.
        /// Browsers and the official comms apps are skipped.
        /// </summary>
        public static WebhookKind ClassifyWebhook(
            string? processName,
            string? imagePath,
            bool hasHttps,
            bool dedicatedDnsRecently,
            bool commsDnsRecently,
            bool urlInContent)
        {
            // Identity skip (real Discord/Chrome/games). URL-in-content still
            // wins for curl/IWR in Downloads - those are not comms identity.
            if (IsKnownCommsIdentity(processName, imagePath) ||
                IsVpnOrIkeIdentity(processName, imagePath) ||
                AlwaysOnPolicies.IsProtectedGamePath(imagePath) ||
                InstallerHeuristics.IsDirectXOrRuntimeRedist(processName, imagePath))
                return WebhookKind.None;

            var n = NormalizeProcessName(processName);
            if ((n.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                 n.Equals("system", StringComparison.OrdinalIgnoreCase) ||
                 n.Equals("lsass", StringComparison.OrdinalIgnoreCase)) &&
                SecurityValidation.IsWindowsSystemImage(imagePath))
                return WebhookKind.None;

            // URL on the command line / script wins even for portable Downloads tools (curl IWR).
            if (urlInContent)
                return WebhookKind.UrlInContent;

            if (ShouldSkipWorkSurface(processName, imagePath))
                return WebhookKind.None;

            bool staging = IsScriptHost(processName) || IsSuspiciousPath(imagePath);

            if (dedicatedDnsRecently && (hasHttps || staging))
                return WebhookKind.DedicatedSink;

            if (commsDnsRecently && staging && hasHttps)
                return WebhookKind.CommsPlatformAbuse;

            return WebhookKind.None;
        }

        public static double ConfidenceFor(WebhookKind k) => k switch
        {
            WebhookKind.UrlInContent => 0.90,
            WebhookKind.DedicatedSink => 0.88,
            WebhookKind.CommsPlatformAbuse => 0.86,
            _ => 0,
        };
    }

    /// <summary>
    /// Recent DNS hits on DERP / tailcat bootstrap hosts. Written by
    /// <see cref="DnsQueryMonitor"/>, read by <see cref="CovertMeshMonitor"/>.
    /// ConcurrentDictionary is the allowed shared-state form.
    /// </summary>
    internal static class CovertMeshSightings
    {
        private static readonly ConcurrentDictionary<string, long> Domains =
            new(StringComparer.OrdinalIgnoreCase);

        public static void NoteDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain)) return;
            if (!UserlandProtocolHeuristics.IsCovertMeshDomain(domain)) return;
            Domains[domain] = DateTime.UtcNow.Ticks;
            if (Domains.Count > 256)
            {
                var cutoff = DateTime.UtcNow.AddMinutes(-15).Ticks;
                foreach (var kv in Domains)
                {
                    if (kv.Value < cutoff)
                        Domains.TryRemove(kv.Key, out _);
                }
            }
        }

        public static bool SeenRecently(TimeSpan window)
        {
            long cutoff = DateTime.UtcNow.Subtract(window).Ticks;
            foreach (var kv in Domains)
            {
                if (kv.Value >= cutoff) return true;
            }
            return false;
        }
    }

    /// <summary>
    /// Recent DNS hits on webhook / bot-API hosts. Written by
    /// <see cref="DnsQueryMonitor"/>, read by <see cref="CovertWebhookMonitor"/>.
    /// </summary>
    internal static class CovertWebhookSightings
    {
        private static readonly ConcurrentDictionary<string, long> Dedicated =
            new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<int, long> CommsPids = new();

        public static void NoteDomain(string domain, int pid)
        {
            if (string.IsNullOrWhiteSpace(domain)) return;
            long now = DateTime.UtcNow.Ticks;
            if (UserlandProtocolHeuristics.IsDedicatedWebhookSink(domain))
                Dedicated[domain] = now;
            else if (UserlandProtocolHeuristics.IsCommsExfilHost(domain) && pid > 4)
                CommsPids[pid] = now;
            else
                return;

            if (Dedicated.Count > 256)
            {
                long cutoff = DateTime.UtcNow.AddMinutes(-15).Ticks;
                foreach (var kv in Dedicated)
                {
                    if (kv.Value < cutoff)
                        Dedicated.TryRemove(kv.Key, out _);
                }
            }
            if (CommsPids.Count > 512)
            {
                long cutoff = DateTime.UtcNow.AddMinutes(-15).Ticks;
                foreach (var kv in CommsPids)
                {
                    if (kv.Value < cutoff)
                        CommsPids.TryRemove(kv.Key, out _);
                }
            }
        }

        public static bool SeenDedicatedRecently(TimeSpan window)
        {
            long cutoff = DateTime.UtcNow.Subtract(window).Ticks;
            foreach (var kv in Dedicated)
            {
                if (kv.Value >= cutoff) return true;
            }
            return false;
        }

        public static bool SeenCommsFor(int pid, TimeSpan window)
        {
            if (pid <= 4) return false;
            if (!CommsPids.TryGetValue(pid, out var ticks)) return false;
            return ticks >= DateTime.UtcNow.Subtract(window).Ticks;
        }
    }

    /// <summary>
    /// Cross-monitor enrichment for userland protocol events (WFP / UDP binds).
    /// Consumed by VoipSessionMonitor. Not a detection.
    /// </summary>
    public sealed class ProtocolFlowSignal : EnrichmentSignal
    {
        public string Protocol { get; set; } = string.Empty;
        public byte IpProtocol { get; set; }
        public string LocalAddress { get; set; } = string.Empty;
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; } = string.Empty;
        public int RemotePort { get; set; }
        public string ImagePath { get; set; } = string.Empty;
        public string WfpEventType { get; set; } = string.Empty;
    }

    // 
    // UDP Flow Monitor - GetExtendedUdpTable OWNER_PID
    // (bind table; remote peers come from Kernel-Network ETW)
    // 
    public sealed class UdpFlowMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<UdpFlowMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly TelemetryFusionEngine? _fusion;
        private readonly ContextBus? _bus;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(2);

        public UdpFlowMonitor(
            DetectionEngine detectionEngine,
            ILogger<UdpFlowMonitor> logger,
            ProcessAncestryCache? ancestry = null,
            TelemetryFusionEngine? fusion = null,
            ContextBus? bus = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
            _fusion = fusion;
            _bus = bus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[UdpFlowMonitor] Started - UDP bind table (no kernel driver)");
            try { await Task.Delay(TimeSpan.FromSeconds(8), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { ScanBinds(); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[UdpFlowMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private void ScanBinds()
        {
            var binds = NativeUdpTable.Snapshot();
            if (binds.Count == 0) return;

            var counts = new Dictionary<int, int>();
            foreach (var b in binds)
            {
                if (b.Pid <= 4) continue;
                counts[b.Pid] = counts.TryGetValue(b.Pid, out var c) ? c + 1 : 1;
            }

            int myPid = System.Net48Environment.ProcessId;
            foreach (var b in binds)
            {
                if (b.Pid <= 4 || b.Pid == myPid) continue;

                var (name, path) = ProtocolProcessLookup.Resolve(b.Pid, _ancestry);
                int n = counts.TryGetValue(b.Pid, out var c) ? c : 1;
                var kind = UserlandProtocolHeuristics.ClassifyUdpBind(name, path, b.LocalPort, n);
                if (kind == UserlandProtocolHeuristics.UdpVerdictKind.None) continue;

                _ = EmitUdpAsync(kind, name, path, b.Pid, b.LocalAddress, b.LocalPort, n);

                _bus?.Publish(new ProtocolFlowSignal
                {
                    SourceMonitor = nameof(UdpFlowMonitor),
                    ProcessId = b.Pid,
                    ProcessName = name,
                    Protocol = "UDP",
                    IpProtocol = UserlandProtocolHeuristics.ProtoUdp,
                    LocalAddress = b.LocalAddress,
                    LocalPort = b.LocalPort,
                    ImagePath = path ?? "",
                    Ttl = TimeSpan.FromMinutes(2),
                });
            }
        }

        private async Task EmitUdpAsync(
            UserlandProtocolHeuristics.UdpVerdictKind kind,
            string name, string? path, int pid, string local, int port, int sockets)
        {
            string rule = kind switch
            {
                UserlandProtocolHeuristics.UdpVerdictKind.LolbinDatagram =>
                    "Network UDP: LOLBin Datagram",
                UserlandProtocolHeuristics.UdpVerdictKind.SuspiciousPath =>
                    "Network UDP: Datagram from Suspicious Path",
                UserlandProtocolHeuristics.UdpVerdictKind.ClassicMalwarePort =>
                    "Network UDP: Classic Malware Port",
                UserlandProtocolHeuristics.UdpVerdictKind.SocketExplosion =>
                    "Network UDP: Socket Explosion",
                _ => "Network UDP: Anomaly",
            };

            string key = $"{rule}:{pid}:{port}";
            if (!ShouldAlert(key)) return;

            bool weak = kind == UserlandProtocolHeuristics.UdpVerdictKind.SuspiciousPath ||
                        kind == UserlandProtocolHeuristics.UdpVerdictKind.SocketExplosion;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"UDP bind {local}:{port} by '{name}' (PID {pid})" +
                           (sockets > 1 ? $", {sockets} UDP sockets" : ""),
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.UdpVerdictKind.LolbinDatagram =>
                        "A script host / LOLBin bound a UDP socket. UDP is a common C2 and tunneling channel " +
                        "(DNS, QUIC, custom datagram C2) that TCP-only monitors miss. LogOnly; kill requires a chain.",
                    UserlandProtocolHeuristics.UdpVerdictKind.SuspiciousPath =>
                        "A binary from Temp/Downloads bound UDP. Common for portable tools; logged only.",
                    UserlandProtocolHeuristics.UdpVerdictKind.ClassicMalwarePort =>
                        $"UDP port {port} is a classic malware/legacy-service port (TFTP/SNMP/Slammer/RAT). Weak indicator.",
                    UserlandProtocolHeuristics.UdpVerdictKind.SocketExplosion =>
                        "One process holds an unusually large UDP bind set - scan, stun-harvest, or datagram C2 fan-out. LogOnly.",
                    _ => "UDP bind anomaly.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind),
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = ProtocolEmitMeta.Create(path, local, port, weak, "UDP"),
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 400) _alerted.Clear();
                return true;
            }
        }
    }

    // 
    // ICMP Anomaly Monitor - GetIcmpStatisticsEx (IPv4+IPv6)
    // 
    public sealed class IcmpAnomalyMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<IcmpAnomalyMonitor> _logger;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(5);

        private NativeIcmp.Snapshot? _prev;
        private DateTime _prevAt;
        private int _baselineTicks;
        private const int BaselineTicksRequired = 3;

        public IcmpAnomalyMonitor(DetectionEngine detectionEngine, ILogger<IcmpAnomalyMonitor> logger)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[IcmpAnomalyMonitor] Started - ICMP type counters (no kernel driver)");
            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { await ScanAsync().ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[IcmpAnomalyMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanAsync()
        {
            var cur = NativeIcmp.Read();
            var now = DateTime.UtcNow;
            if (_prev == null)
            {
                _prev = cur;
                _prevAt = now;
                return;
            }

            double secs = Math.Max(1.0, (now - _prevAt).TotalSeconds);
            uint echoDelta = SaturatingAdd(
                SaturatingSub(cur.InEcho, _prev.InEcho),
                SaturatingSub(cur.OutEcho, _prev.OutEcho));
            uint unreachDelta = SaturatingSub(cur.InUnreach, _prev.InUnreach);
            uint redirectDelta = SaturatingSub(cur.InRedirect, _prev.InRedirect);

            uint echoPerSec = (uint)(echoDelta / secs);
            uint unreachPerSec = (uint)(unreachDelta / secs);

            _prev = cur;
            _prevAt = now;
            if (_baselineTicks < BaselineTicksRequired)
            {
                _baselineTicks++;
                return;
            }

            var kind = UserlandProtocolHeuristics.ClassifyIcmpDelta(
                echoPerSec, redirectDelta, unreachPerSec, true);
            if (kind == UserlandProtocolHeuristics.IcmpVerdictKind.None) return;

            string rule = kind switch
            {
                UserlandProtocolHeuristics.IcmpVerdictKind.RedirectInbound =>
                    "Network ICMP: Redirect Inbound",
                UserlandProtocolHeuristics.IcmpVerdictKind.EchoFlood =>
                    "Network ICMP: Echo Flood",
                UserlandProtocolHeuristics.IcmpVerdictKind.UnreachableStorm =>
                    "Network ICMP: Unreachable Storm",
                _ => "Network ICMP: Anomaly",
            };

            string key = rule;
            if (!ShouldAlert(key)) return;

            bool weak = kind != UserlandProtocolHeuristics.IcmpVerdictKind.RedirectInbound;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"ICMP delta {secs:0.0}s: echo={echoPerSec}/s unreach={unreachPerSec}/s inbound-redirects={redirectDelta}",
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.IcmpVerdictKind.RedirectInbound =>
                        "Inbound ICMP Redirects (type 5 / ICMPv6 137) after a quiet baseline. Classic on-path MITM " +
                        "to poison the host route table. Userland cannot see the packet payload without a driver; " +
                        "the type counter is the honest signal. LogOnly.",
                    UserlandProtocolHeuristics.IcmpVerdictKind.EchoFlood =>
                        "ICMP echo rate exceeded the observe threshold. Could be a ping flood, ICMP tunnel, or a " +
                        "noisy diagnostic. Games and user pings are common; LogOnly.",
                    UserlandProtocolHeuristics.IcmpVerdictKind.UnreachableStorm =>
                        "Destination-unreachable storm - port/host scan residue or path failure. LogOnly.",
                    _ => "ICMP anomaly.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind),
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    ["Protocol"] = "ICMP",
                    ["EchoPerSec"] = echoPerSec.ToString(),
                    ["UnreachPerSec"] = unreachPerSec.ToString(),
                    ["InboundRedirects"] = redirectDelta.ToString(),
                    ["WeakObserveSeed"] = weak ? "true" : "false",
                },
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 32) _alerted.Clear();
                return true;
            }
        }

        private static uint SaturatingSub(uint a, uint b) => a >= b ? a - b : 0;
        private static uint SaturatingAdd(uint a, uint b) => a > uint.MaxValue - b ? uint.MaxValue : a + b;
    }

    // 
    // WFP Net Event Monitor - FwpmNetEventSubscribe0 (user-mode BFE)
    // Covers TCP/UDP/ICMP plus GRE/ESP/AH/SCTP/L2TP/encap.
    // Does not add filters, does not enable audit policy.
    // 
    public sealed class WfpNetEventMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<WfpNetEventMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly TelemetryFusionEngine? _fusion;
        private readonly ContextBus? _bus;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<int, int> _dropBurst = new();
        private DateTime _dropWindowStart = DateTime.UtcNow;

        private IntPtr _engine;
        private IntPtr _subscription;
        private FwpmNative.NetEventCallback? _callback;
        private bool _subscribed;
        private DateTime _wfpLastEventUtc;

        public WfpNetEventMonitor(
            DetectionEngine detectionEngine,
            ILogger<WfpNetEventMonitor> logger,
            ProcessAncestryCache? ancestry = null,
            TelemetryFusionEngine? fusion = null,
            ContextBus? bus = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
            _fusion = fusion;
            _bus = bus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[WfpNetEventMonitor] Started - WFP net-event subscribe (fwpuclnt, no callout driver)");
            try { await Task.Delay(TimeSpan.FromSeconds(12), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            TrySubscribe();

            while (!ct.IsCancellationRequested)
            {
                try
                {
                    if (!_subscribed)
                        TrySubscribe();
                    else if (DateTime.UtcNow - _wfpLastEventUtc > TimeSpan.FromMinutes(8) &&
                             _wfpLastEventUtc != default)
                    {
                        Unsubscribe();
                        TrySubscribe();
                    }
                    await PollUnknownProtosAsync().ConfigureAwait(false);
                    PruneDropWindow();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[WfpNetEventMonitor] loop error"); }

                try { await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }

            Unsubscribe();
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            Unsubscribe();
            await base.StopAsync(cancellationToken).ConfigureAwait(false);
        }

        private void TrySubscribe()
        {
            if (_subscribed) return;
            try
            {
                uint err = FwpmNative.FwpmEngineOpen0(null, FwpmNative.RpcCAuthnWinnt, IntPtr.Zero, IntPtr.Zero, out _engine);
                if (err != 0 || _engine == IntPtr.Zero)
                {
                    _logger.LogDebug("[WfpNetEventMonitor] FwpmEngineOpen0 failed 0x{Err:X8} - will retry; ICMP/UDP monitors still cover datagrams", err);
                    return;
                }

                FwpmNative.TryEnableNetEventCollection(_engine);

                _callback = OnNetEvent;
                var sub = new FwpmNative.FWPM_NET_EVENT_SUBSCRIPTION0
                {
                    enumTemplate = IntPtr.Zero,
                    flags = 0,
                    sessionKey = Guid.Empty,
                };
                err = FwpmNative.FwpmNetEventSubscribe0(
                    _engine, ref sub, Marshal.GetFunctionPointerForDelegate(_callback), IntPtr.Zero, out _subscription);
                if (err != 0)
                {
                    _logger.LogDebug("[WfpNetEventMonitor] FwpmNetEventSubscribe0 failed 0x{Err:X8} - BFE net events unavailable on this host", err);
                    FwpmNative.FwpmEngineClose0(_engine);
                    _engine = IntPtr.Zero;
                    _callback = null;
                    return;
                }

                _subscribed = true;
                _wfpLastEventUtc = DateTime.UtcNow;
                _logger.LogInformation("[WfpNetEventMonitor] Subscribed to WFP net events");
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WfpNetEventMonitor] subscribe failed - graceful degrade");
                Unsubscribe();
            }
        }

        private void Unsubscribe()
        {
            _subscribed = false;
            try
            {
                if (_engine != IntPtr.Zero && _subscription != IntPtr.Zero)
                    FwpmNative.FwpmNetEventUnsubscribe0(_engine, _subscription);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[WfpNetEventMonitor] unsubscribe"); }
            _subscription = IntPtr.Zero;
            try
            {
                if (_engine != IntPtr.Zero)
                    FwpmNative.FwpmEngineClose0(_engine);
            }
            catch (Exception ex) { _logger.LogDebug(ex, "[WfpNetEventMonitor] engine close"); }
            _engine = IntPtr.Zero;
            _callback = null;
        }

        private void OnNetEvent(IntPtr context, IntPtr netEvent)
        {
            if (netEvent == IntPtr.Zero) return;
            _wfpLastEventUtc = DateTime.UtcNow;
            try
            {
                if (!FwpmNative.TryParseHeader(netEvent, out var parsed)) return;
                HandleParsed(parsed);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[WfpNetEventMonitor] callback parse");
            }
        }

        private void HandleParsed(FwpmNative.ParsedNetEvent ev)
        {
            var (name, path) = string.IsNullOrEmpty(ev.AppPath)
                ? ProtocolProcessLookup.Resolve(ev.Pid, _ancestry)
                : (ProtocolProcessLookup.NameFromPath(ev.AppPath), ev.AppPath);

            if (ev.Pid > 4)
            {
                var telemetry = new NetworkTelemetry
                {
                    Type = "WfpNetEvent",
                    ProcessId = ev.Pid,
                    ProcessName = name,
                    LocalAddress = ev.LocalAddress,
                    LocalPort = ev.LocalPort,
                    RemoteAddress = ev.RemoteAddress,
                    RemotePort = ev.RemotePort,
                    Protocol = UserlandProtocolHeuristics.IpProtocolName(ev.IpProtocol),
                    State = ev.EventType == UserlandProtocolHeuristics.WfpTypeClassifyDrop ? "DROP" : "EVENT",
                    Timestamp = DateTime.UtcNow,
                };
                if (_fusion != null)
                {
                    var ctx = _fusion.FeedEvent(telemetry);
                    _detectionEngine.SubmitTelemetry(ctx);
                }

                _bus?.Publish(new ProtocolFlowSignal
                {
                    SourceMonitor = nameof(WfpNetEventMonitor),
                    ProcessId = ev.Pid,
                    ProcessName = name,
                    Protocol = telemetry.Protocol,
                    IpProtocol = ev.IpProtocol,
                    LocalAddress = ev.LocalAddress,
                    LocalPort = ev.LocalPort,
                    RemoteAddress = ev.RemoteAddress,
                    RemotePort = ev.RemotePort,
                    ImagePath = path ?? "",
                    WfpEventType = ev.EventType.ToString(),
                    Ttl = TimeSpan.FromMinutes(2),
                });
            }

            var kind = UserlandProtocolHeuristics.ClassifyWfpEvent(ev.IpProtocol, ev.EventType, name, path);
            if (kind == UserlandProtocolHeuristics.WfpVerdictKind.None) return;

            if (kind == UserlandProtocolHeuristics.WfpVerdictKind.ClassifyDrop)
            {
                int pidKey = ev.Pid > 0 ? ev.Pid : 0;
                int n = _dropBurst.AddOrUpdate(pidKey, 1, (_, old) => old + 1);
                if (n < 25) return;
                kind = UserlandProtocolHeuristics.WfpVerdictKind.ClassifyDrop;
            }

            _ = EmitWfpAsync(kind, name, path, ev);
        }

        private async Task EmitWfpAsync(
            UserlandProtocolHeuristics.WfpVerdictKind kind,
            string name, string? path, FwpmNative.ParsedNetEvent ev)
        {
            string rule = kind switch
            {
                UserlandProtocolHeuristics.WfpVerdictKind.UnusualIpProtocol =>
                    "Network WFP: Unusual IP Protocol",
                UserlandProtocolHeuristics.WfpVerdictKind.IPsecKernelDrop =>
                    "Network WFP: IPsec Kernel Drop",
                UserlandProtocolHeuristics.WfpVerdictKind.ClassifyDrop =>
                    "Network WFP: Classify Drop Burst",
                _ => "Network WFP: Net Event",
            };

            string proto = UserlandProtocolHeuristics.IpProtocolName(ev.IpProtocol);
            string key = $"{rule}:{ev.Pid}:{proto}:{ev.RemotePort}";
            if (!ShouldAlert(key)) return;

            bool weak = kind == UserlandProtocolHeuristics.WfpVerdictKind.ClassifyDrop;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"WFP type={ev.EventType} proto={proto}({ev.IpProtocol}) " +
                           $"{ev.LocalAddress}:{ev.LocalPort} -> {ev.RemoteAddress}:{ev.RemotePort} " +
                           $"app='{name}' PID={ev.Pid}",
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.WfpVerdictKind.UnusualIpProtocol =>
                        $"Non-TCP/UDP IP protocol {proto} observed via the Windows Filtering Platform user-mode " +
                        "subscription (FwpmNetEventSubscribe). Covers GRE/ESP/AH/SCTP/L2TP/IPv6-encap without a " +
                        "callout driver. VPN IKE/ESP from svchost is skipped. LogOnly.",
                    UserlandProtocolHeuristics.WfpVerdictKind.IPsecKernelDrop =>
                        "WFP reported an IPsec kernel drop. Can be a broken VPN or an attempt to inject into an " +
                        "IPsec SA. LogOnly.",
                    UserlandProtocolHeuristics.WfpVerdictKind.ClassifyDrop =>
                        "Burst of WFP classify-drops for one app - scan, exploit spray, or a firewall fight. LogOnly.",
                    _ => "WFP net event.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind),
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = string.IsNullOrEmpty(name) ? "SYSTEM" : name,
                ProcessId = ev.Pid,
                SignalType = SignalType.SuspiciousProcess,
                Metadata = ProtocolEmitMeta.Create(path, ev.RemoteAddress, ev.RemotePort, weak, proto),
            }).ConfigureAwait(false);
        }

        private uint _lastUnknownProtos;
        private bool _unknownBaseline;

        private async Task PollUnknownProtosAsync()
        {
            uint unknown = NativeIpStats.InUnknownProtos();
            if (!_unknownBaseline)
            {
                _lastUnknownProtos = unknown;
                _unknownBaseline = true;
                return;
            }

            if (unknown <= _lastUnknownProtos)
            {
                _lastUnknownProtos = unknown;
                return;
            }

            uint delta = unknown - _lastUnknownProtos;
            _lastUnknownProtos = unknown;
            if (delta < 32) return;
            if (!ShouldAlert("Network WFP: Unknown IP Protocol Counter")) return;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = "Network WFP: Unusual IP Protocol",
                Evidence = $"GetIpStatisticsEx dwInUnknownProtos rose by {delta} (now {unknown})",
                Reasoning = "The IP stack delivered datagrams with a protocol number it does not handle. " +
                            "Fallback when WFP net events are not collected on this host. LogOnly.",
                Confidence = 0.48,
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = "SYSTEM",
                ProcessId = 0,
                SignalType = SignalType.Generic,
                Metadata = new Dictionary<string, string>
                {
                    ["Protocol"] = "IP-unknown",
                    ["UnknownProtoDelta"] = delta.ToString(),
                    ["WeakObserveSeed"] = "true",
                },
            }).ConfigureAwait(false);
        }

        private void PruneDropWindow()
        {
            var now = DateTime.UtcNow;
            if (now - _dropWindowStart < TimeSpan.FromSeconds(30)) return;
            _dropWindowStart = now;
            _dropBurst.Clear();
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 400) _alerted.Clear();
                return true;
            }
        }
    }

    // 
    // VoIP Session Monitor - SIP/STUN/H.323/IAX/MGCP + RTP-like binds
    // Work-first: Discord/Teams/Zoom/Steam/browsers never emit.
    // 
    public sealed class VoipSessionMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<VoipSessionMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly ContextBus? _bus;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private IDisposable? _subscription;
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(3);

        public VoipSessionMonitor(
            DetectionEngine detectionEngine,
            ILogger<VoipSessionMonitor> logger,
            ProcessAncestryCache? ancestry = null,
            ContextBus? bus = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
            _bus = bus;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[VoipSessionMonitor] Started - SIP/STUN/RTP-like UDP binds (no packet capture)");
            _subscription = _bus?.Subscribe<ProtocolFlowSignal>(OnProtocolFlowAsync, nameof(VoipSessionMonitor));

            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { await ScanBindsAsync().ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[VoipSessionMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }

            _subscription?.Dispose();
            _subscription = null;
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _subscription?.Dispose();
            _subscription = null;
            await base.StopAsync(cancellationToken).ConfigureAwait(false);
        }

        private Task OnProtocolFlowAsync(ProtocolFlowSignal signal)
        {
            if (signal == null || signal.IsExpired) return Task.CompletedTask;
            int port = signal.RemotePort > 0 ? signal.RemotePort : signal.LocalPort;
            if (!UserlandProtocolHeuristics.IsVoipSignalingPort(port)) return Task.CompletedTask;
            return ConsiderAsync(signal.ProcessName, signal.ImagePath, signal.ProcessId, port, rtpCount: 0, signaling: true);
        }

        private async Task ScanBindsAsync()
        {
            var binds = NativeUdpTable.Snapshot();
            var rtpCounts = new Dictionary<int, int>();
            foreach (var b in binds)
            {
                if (b.Pid <= 4) continue;
                if (UserlandProtocolHeuristics.IsClassicRtpPort(b.LocalPort))
                    rtpCounts[b.Pid] = rtpCounts.TryGetValue(b.Pid, out var n) ? n + 1 : 1;
            }

            int myPid = System.Net48Environment.ProcessId;
            foreach (var b in binds)
            {
                if (b.Pid <= 4 || b.Pid == myPid) continue;
                var (name, path) = ProtocolProcessLookup.Resolve(b.Pid, _ancestry);
                bool signaling = UserlandProtocolHeuristics.IsVoipSignalingPort(b.LocalPort);
                int rtp = rtpCounts.TryGetValue(b.Pid, out var c) ? c : 0;
                await ConsiderAsync(name, path, b.Pid, b.LocalPort, rtp, signaling).ConfigureAwait(false);
            }
        }

        private async Task ConsiderAsync(
            string name, string? path, int pid, int port, int rtpCount, bool signaling)
        {
            var kind = UserlandProtocolHeuristics.ClassifyVoip(name, path, port, rtpCount, signaling);
            if (kind == UserlandProtocolHeuristics.VoipVerdictKind.None) return;

            string rule = kind switch
            {
                UserlandProtocolHeuristics.VoipVerdictKind.SipUnexpected =>
                    "Network VoIP: SIP from Unexpected Process",
                UserlandProtocolHeuristics.VoipVerdictKind.StunUnexpected =>
                    "Network VoIP: STUN/TURN from Unexpected Process",
                UserlandProtocolHeuristics.VoipVerdictKind.HiddenRtpBinds =>
                    "Network VoIP: Hidden RTP-like Binds",
                _ => "Network VoIP: Session",
            };

            string key = $"{rule}:{pid}:{port}";
            if (!ShouldAlert(key)) return;

            bool script = UserlandProtocolHeuristics.IsScriptHost(name);
            string label = UserlandProtocolHeuristics.VoipPortLabel(port);

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"{label} UDP port {port} on '{name}' (PID {pid})" +
                           (rtpCount > 0 ? $", {rtpCount} RTP-like binds" : "") +
                           (string.IsNullOrEmpty(path) ? "" : $", path={path}"),
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.VoipVerdictKind.SipUnexpected =>
                        "SIP (5060/5061) from a process that is not a known comms/game/browser app. " +
                        "Stalkerware and covert RATs reuse SIP; Discord/Teams/Zoom are skipped. " +
                        "Userland cannot parse SIP payloads without a driver. LogOnly observe fuel.",
                    UserlandProtocolHeuristics.VoipVerdictKind.StunUnexpected =>
                        "STUN/TURN/H.323/IAX signaling from an unexpected process. WebRTC in Chrome/Edge is skipped. " +
                        "A LOLBin doing STUN is a hidden media/C2 channel. LogOnly.",
                    UserlandProtocolHeuristics.VoipVerdictKind.HiddenRtpBinds =>
                        "A script host or Temp/Downloads binary holds multiple even UDP ports in the classic RTP band. " +
                        "That is the userland shape of a hidden voice session. Known comms apps never reach this rule.",
                    _ => "VoIP-like UDP session.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind, script),
                Tier = DetectionTier.Tier2Indicator,
                AuthorizedResponse = ResponseAction.LogOnly,
                ProcessName = name,
                ProcessId = pid,
                SignalType = script ? SignalType.SuspiciousProcess : SignalType.Generic,
                Metadata = ProtocolEmitMeta.Create(path, "udp", port, weak: false, label),
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 300) _alerted.Clear();
                return true;
            }
        }
    }

    /// <summary>
    /// Tailcat-class userspace mesh: WireGuard-go + magicsock STUN + DERP HTTPS
    /// with no virtual NIC and no Tailscale control plane. Same shape as
    /// wireproxy, boringtun, sliver WG C2, innernet, renamed binaries.
    /// No packet capture - UDP bind table + TCP 443 + DNS sightings.
    /// </summary>
    public sealed class CovertMeshMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CovertMeshMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(3);

        public CovertMeshMonitor(
            DetectionEngine detectionEngine,
            ILogger<CovertMeshMonitor> logger,
            ProcessAncestryCache? ancestry = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CovertMeshMonitor] Started - userspace WireGuard/DERP/STUN overlays (tailcat-class)");
            try { await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { await ScanAsync().ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CovertMeshMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanAsync()
        {
            var udp = NativeUdpTable.Snapshot();
            var httpsPids = NativeTcpTable.HttpsOwnerPids();
            bool meshDns = CovertMeshSightings.SeenRecently(TimeSpan.FromMinutes(10));

            var udpCounts = new Dictionary<int, int>();
            var stunPids = new HashSet<int>();
            foreach (var b in udp)
            {
                if (b.Pid <= 4) continue;
                if (UserlandProtocolHeuristics.IsAmbientUdp(b.LocalPort, null))
                    continue;
                udpCounts[b.Pid] = udpCounts.TryGetValue(b.Pid, out var n) ? n + 1 : 1;
                if (UserlandProtocolHeuristics.IsStunTurnPort(b.LocalPort))
                    stunPids.Add(b.Pid);
            }

            int myPid = System.Net48Environment.ProcessId;
            var pids = new HashSet<int>(udpCounts.Keys);
            foreach (var p in httpsPids) pids.Add(p);

            foreach (var pid in pids)
            {
                if (pid <= 4 || pid == myPid) continue;
                var (name, path) = ProtocolProcessLookup.Resolve(pid, _ancestry);
                int udpN = udpCounts.TryGetValue(pid, out var c) ? c : 0;
                bool stun = stunPids.Contains(pid);
                bool https = httpsPids.Contains(pid);

                var kind = UserlandProtocolHeuristics.ClassifyCovertMesh(
                    name, path, udpN, stun, https, meshDns);
                if (kind == UserlandProtocolHeuristics.CovertMeshKind.None) continue;

                await EmitAsync(kind, name, path, pid, udpN, stun, https, meshDns).ConfigureAwait(false);
            }
        }

        private async Task EmitAsync(
            UserlandProtocolHeuristics.CovertMeshKind kind,
            string name, string? path, int pid, int udpN, bool stun, bool https, bool meshDns)
        {
            string rule = kind switch
            {
                UserlandProtocolHeuristics.CovertMeshKind.NamedTool =>
                    "Covert Mesh: Userspace Overlay Tool",
                UserlandProtocolHeuristics.CovertMeshKind.DerpRelay =>
                    "Covert Mesh: DERP Relay + UDP",
                UserlandProtocolHeuristics.CovertMeshKind.StunHolePunch =>
                    "Covert Mesh: STUN Hole-Punch Overlay",
                UserlandProtocolHeuristics.CovertMeshKind.UserWritableOverlay =>
                    "Covert Mesh: User-Writable UDP+HTTPS Overlay",
                _ => "Covert Mesh: Overlay",
            };

            string key = $"{rule}:{pid}";
            if (!ShouldAlert(key)) return;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"'{name}' (PID {pid}) udpBinds={udpN} https443={https} stun={stun} derpDns={meshDns}" +
                           (string.IsNullOrEmpty(path) ? "" : $", path={path}"),
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.CovertMeshKind.NamedTool =>
                        "A userspace mesh/overlay binary (tailcat, wireproxy, boringtun, sliver WG, innernet, ...) " +
                        "is running. WireGuard in-process, no TAP/Wintun, no Tailscale control plane - covert C2. " +
                        "Official tailscale.exe is not this rule. Kill-grade C2.",
                    UserlandProtocolHeuristics.CovertMeshKind.DerpRelay =>
                        "UDP overlay plus DERP/tailcat bootstrap DNS from this PID. Magicsock C2, not the " +
                        "installed Tailscale client. Kill-grade C2.",
                    UserlandProtocolHeuristics.CovertMeshKind.StunHolePunch =>
                        "STUN/TURN plus UDP from a process that is not a browser, game, or comms app. " +
                        "Userspace hole-punch tunnel. Kill-grade C2.",
                    UserlandProtocolHeuristics.CovertMeshKind.UserWritableOverlay =>
                        "Temp/Downloads/script-host UDP overlay with HTTPS - tailcat-class bootstrap. Kill-grade C2.",
                    _ => "Userspace mesh overlay.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind),
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.NetworkC2,
                Family = TerminalFamily.C2Beacon,
                Metadata = ProtocolEmitMeta.Create(path, "mesh", udpN, weak: false, "UDP+HTTPS"),
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 200) _alerted.Clear();
                return true;
            }
        }
    }

    /// <summary>
    /// Stealers' webhook exfil without TLS intercept: DNS to a callback sink
    /// or Discord/Telegram/Slack bot host, plus HTTPS, from a script host or
    /// Temp/Downloads. Official Discord/Slack/Telegram and browsers skipped.
    /// </summary>
    public sealed class CovertWebhookMonitor : BackgroundService
    {
        private readonly DetectionEngine _detectionEngine;
        private readonly ILogger<CovertWebhookMonitor> _logger;
        private readonly ProcessAncestryCache? _ancestry;
        private readonly HashSet<string> _alerted = new(StringComparer.OrdinalIgnoreCase);
        private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(4);

        public CovertWebhookMonitor(
            DetectionEngine detectionEngine,
            ILogger<CovertWebhookMonitor> logger,
            ProcessAncestryCache? ancestry = null)
        {
            _detectionEngine = detectionEngine;
            _logger = logger;
            _ancestry = ancestry;
        }

        protected override async Task ExecuteAsync(CancellationToken ct)
        {
            _logger.LogInformation("[CovertWebhookMonitor] Started - webhook/bot-API exfil from unexpected processes");
            try { await Task.Delay(TimeSpan.FromSeconds(12), ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { return; }

            while (!ct.IsCancellationRequested)
            {
                try { await ScanAsync().ConfigureAwait(false); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "[CovertWebhookMonitor] scan error"); }

                try { await Task.Delay(ScanInterval, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
        }

        private async Task ScanAsync()
        {
            var httpsPids = NativeTcpTable.HttpsOwnerPids();
            bool dedicatedDns = CovertWebhookSightings.SeenDedicatedRecently(TimeSpan.FromMinutes(10));
            if (!dedicatedDns && httpsPids.Count == 0)
                return;

            int myPid = System.Net48Environment.ProcessId;
            foreach (var pid in httpsPids)
            {
                if (pid <= 4 || pid == myPid) continue;
                var (name, path) = ProtocolProcessLookup.Resolve(pid, _ancestry);
                bool commsDns = CovertWebhookSightings.SeenCommsFor(pid, TimeSpan.FromMinutes(10));
                var kind = UserlandProtocolHeuristics.ClassifyWebhook(
                    name, path, hasHttps: true, dedicatedDns, commsDns, urlInContent: false);
                if (kind == UserlandProtocolHeuristics.WebhookKind.None) continue;

                await EmitAsync(kind, name, path, pid, https: true, dedicatedDns, commsDns, urlInContent: false)
                    .ConfigureAwait(false);
            }

            if (!dedicatedDns) return;

            // Dedicated-sink DNS with no HTTPS yet (lookup then POST). Script hosts only.
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (p.Id <= 4 || p.Id == myPid || httpsPids.Contains(p.Id)) continue;
                    if (!UserlandProtocolHeuristics.IsScriptHost(p.ProcessName)) continue;
                    var (name, path) = ProtocolProcessLookup.Resolve(p.Id, _ancestry);
                    var kind = UserlandProtocolHeuristics.ClassifyWebhook(
                        name, path, hasHttps: false, dedicatedDnsRecently: true,
                        commsDnsRecently: false, urlInContent: false);
                    if (kind == UserlandProtocolHeuristics.WebhookKind.None) continue;
                    await EmitAsync(kind, name, path, p.Id, https: false, dedicatedDns, commsDns: false, urlInContent: false)
                        .ConfigureAwait(false);
                }
                catch { /* process exited */ }
                finally { p.Dispose(); }
            }
        }

        private async Task EmitAsync(
            UserlandProtocolHeuristics.WebhookKind kind,
            string name, string? path, int pid, bool https, bool dedicatedDns, bool commsDns, bool urlInContent)
        {
            string rule = kind switch
            {
                UserlandProtocolHeuristics.WebhookKind.DedicatedSink =>
                    "Covert Webhook: Disposable Sink",
                UserlandProtocolHeuristics.WebhookKind.CommsPlatformAbuse =>
                    "Covert Webhook: Comms Platform from Unexpected Process",
                UserlandProtocolHeuristics.WebhookKind.UrlInContent =>
                    "Covert Webhook: URL in Command Line",
                _ => "Covert Webhook: Exfil",
            };

            string key = $"{rule}:{pid}";
            if (!ShouldAlert(key)) return;

            await _detectionEngine.EmitAsync(new DetectionEvent
            {
                RuleName = rule,
                Evidence = $"'{name}' (PID {pid}) https={https} dedicatedSinkDns={dedicatedDns} " +
                           $"commsDns={commsDns} urlInCmd={urlInContent}" +
                           (string.IsNullOrEmpty(path) ? "" : $", path={path}"),
                Reasoning = kind switch
                {
                    UserlandProtocolHeuristics.WebhookKind.DedicatedSink =>
                        "A non-browser process contacted a disposable HTTP callback host " +
                        "(webhook.site, interact.sh, requestbin, canarytokens). Stealer exfil sink. Kill-grade C2.",
                    UserlandProtocolHeuristics.WebhookKind.CommsPlatformAbuse =>
                        "Script host or Temp/Downloads binary has HTTPS after Discord/Telegram/Slack bot-API DNS " +
                        "from this PID. Official Discord/Telegram/Slack apps never emit this rule. Kill-grade C2.",
                    UserlandProtocolHeuristics.WebhookKind.UrlInContent =>
                        "A webhook URL is on the command line (curl/IWR stealer). Kill-grade C2.",
                    _ => "Webhook-shaped exfil.",
                },
                Confidence = UserlandProtocolHeuristics.ConfidenceFor(kind),
                Tier = DetectionTier.Tier1Behavioral,
                AuthorizedResponse = ResponseAction.KillProcessTree,
                ProcessName = name,
                ProcessId = pid,
                SignalType = SignalType.NetworkC2,
                Family = TerminalFamily.C2Beacon,
                Metadata = ProtocolEmitMeta.Create(path, "webhook", 443, weak: false, "HTTPS"),
            }).ConfigureAwait(false);
        }

        private bool ShouldAlert(string key)
        {
            lock (_alerted)
            {
                if (_alerted.Contains(key)) return false;
                _alerted.Add(key);
                if (_alerted.Count > 200) _alerted.Clear();
                return true;
            }
        }
    }

    internal static class ProtocolProcessLookup
    {
        public static (string name, string? path) Resolve(int pid, ProcessAncestryCache? ancestry)
        {
            string name = "";
            string? path = null;
            if (ancestry != null)
            {
                try
                {
                    var info = ancestry.GetProcessInfo(pid);
                    if (!string.IsNullOrEmpty(info.name) &&
                        !info.name.Equals("unknown", StringComparison.OrdinalIgnoreCase))
                        name = info.name;
                    if (!string.IsNullOrEmpty(info.imagePath))
                        path = info.imagePath;
                }
                catch { /* ancestry miss is non-fatal */ }
            }

            if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(path))
            {
                try
                {
                    using var p = Process.GetProcessById(pid);
                    if (string.IsNullOrEmpty(name)) name = p.ProcessName;
                }
                catch { /* process exited */ }
                try { path ??= SecurityValidation.GetProcessImagePath(pid); }
                catch { /* path unavailable */ }
            }

            if (string.IsNullOrEmpty(name)) name = "unknown";
            return (name, path);
        }

        public static string NameFromPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return "unknown";
            try
            {
                var file = System.IO.Path.GetFileNameWithoutExtension(path);
                return string.IsNullOrEmpty(file) ? "unknown" : file;
            }
            catch { return "unknown"; }
        }
    }

    internal static class NativeUdpTable
    {
        private const int UdpTableOwnerPid = 1;
        private const uint AfInet = 2;
        private const uint AfInet6 = 23;

        public readonly struct Bind
        {
            public Bind(int pid, string localAddress, int localPort)
            {
                Pid = pid;
                LocalAddress = localAddress;
                LocalPort = localPort;
            }
            public int Pid { get; }
            public string LocalAddress { get; }
            public int LocalPort { get; }
        }

        public static List<Bind> Snapshot()
        {
            var list = new List<Bind>(64);
            Collect(list, AfInet);
            Collect(list, AfInet6);
            return list;
        }

        private static void Collect(List<Bind> list, uint family)
        {
            int size = 0;
            uint ret = GetExtendedUdpTable(IntPtr.Zero, ref size, true, family, UdpTableOwnerPid, 0);
            if (ret != 122 || size <= 4) return;

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedUdpTable(buf, ref size, true, family, UdpTableOwnerPid, 0);
                if (ret != 0) return;
                int count = Marshal.ReadInt32(buf);
                if (count <= 0 || count > 100_000) return;

                if (family == AfInet)
                {
                    // MIB_UDPROW_OWNER_PID: localAddr(4) localPort(4) owningPid(4)
                    int row = 12;
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = IntPtr.Add(buf, 4 + i * row);
                        uint addr = (uint)Marshal.ReadInt32(p, 0);
                        int port = Ntohs((uint)Marshal.ReadInt32(p, 4));
                        int pid = Marshal.ReadInt32(p, 8);
                        var ip = new IPAddress(BitConverter.GetBytes(addr)).ToString();
                        list.Add(new Bind(pid, ip, port));
                    }
                }
                else
                {
                    // MIB_UDP6ROW_OWNER_PID: addr(16) scope(4) port(4) pid(4) = 28
                    int row = 28;
                    var addrBytes = new byte[16];
                    for (int i = 0; i < count; i++)
                    {
                        IntPtr p = IntPtr.Add(buf, 4 + i * row);
                        Marshal.Copy(p, addrBytes, 0, 16);
                        int port = Ntohs((uint)Marshal.ReadInt32(p, 20));
                        int pid = Marshal.ReadInt32(p, 24);
                        var ip = new IPAddress(addrBytes).ToString();
                        list.Add(new Bind(pid, ip, port));
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static int Ntohs(uint portDword) => (int)((portDword & 0xFF) << 8 | (portDword & 0xFF00) >> 8);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedUdpTable(
            IntPtr pUdpTable, ref int pdwSize, bool bOrder, uint ulAf, int tableClass, uint reserved);
    }

    /// <summary>Established TCP owners with remote 443/80 (DERP / HTTPS bootstrap).</summary>
    internal static class NativeTcpTable
    {
        private const int TcpTableOwnerPidAll = 5;
        private const uint AfInet = 2;
        private const uint AfInet6 = 23;
        private const int MibTcpStateEstablished = 5;

        public static HashSet<int> HttpsOwnerPids()
        {
            var pids = new HashSet<int>();
            CollectV4(pids);
            CollectV6(pids);
            return pids;
        }

        private static void CollectV4(HashSet<int> pids)
        {
            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
            if (ret != 122 || size <= 4) return;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buf, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
                if (ret != 0) return;
                int count = Marshal.ReadInt32(buf);
                if (count <= 0 || count > 100_000) return;
                // MIB_TCPROW_OWNER_PID: state(4) localAddr(4) localPort(4) remoteAddr(4) remotePort(4) pid(4)
                int row = 24;
                for (int i = 0; i < count; i++)
                {
                    IntPtr p = IntPtr.Add(buf, 4 + i * row);
                    int state = Marshal.ReadInt32(p, 0);
                    if (state != MibTcpStateEstablished) continue;
                    int rport = Ntohs((uint)Marshal.ReadInt32(p, 16));
                    if (rport != 443 && rport != 80) continue;
                    int pid = Marshal.ReadInt32(p, 20);
                    if (pid > 4) pids.Add(pid);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static void CollectV6(HashSet<int> pids)
        {
            int size = 0;
            uint ret = GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet6, TcpTableOwnerPidAll, 0);
            if (ret != 122 || size <= 4) return;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetExtendedTcpTable(buf, ref size, true, AfInet6, TcpTableOwnerPidAll, 0);
                if (ret != 0) return;
                int count = Marshal.ReadInt32(buf);
                if (count <= 0 || count > 100_000) return;
                // MIB_TCP6ROW_OWNER_PID: localAddr(16) localScope(4) localPort(4)
                //   remoteAddr(16) remoteScope(4) remotePort(4) state(4) pid(4) = 56
                int row = 56;
                for (int i = 0; i < count; i++)
                {
                    IntPtr p = IntPtr.Add(buf, 4 + i * row);
                    int state = Marshal.ReadInt32(p, 48);
                    if (state != MibTcpStateEstablished) continue;
                    int rport = Ntohs((uint)Marshal.ReadInt32(p, 44));
                    if (rport != 443 && rport != 80) continue;
                    int pid = Marshal.ReadInt32(p, 52);
                    if (pid > 4) pids.Add(pid);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static int Ntohs(uint portDword) => (int)((portDword & 0xFF) << 8 | (portDword & 0xFF00) >> 8);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(
            IntPtr pTcpTable, ref int pdwSize, bool bOrder, uint ulAf, int tableClass, uint reserved);
    }

    internal static class NativeIcmp
    {
        public sealed class Snapshot
        {
            public uint InEcho;
            public uint OutEcho;
            public uint InUnreach;
            public uint InRedirect;
        }

        // ICMPv4 types
        private const int V4EchoReply = 0;
        private const int V4Unreach = 3;
        private const int V4Redirect = 5;
        private const int V4Echo = 8;
        // ICMPv6 types
        private const int V6Unreach = 1;
        private const int V6Echo = 128;
        private const int V6EchoReply = 129;
        private const int V6Redirect = 137;

        public static Snapshot Read()
        {
            var s = new Snapshot();
            Accumulate(s, 2, v4: true);
            Accumulate(s, 23, v4: false);
            return s;
        }

        private static void Accumulate(Snapshot s, uint family, bool v4)
        {
            const int typeCount = 256;
            const int statsSize = 8 + typeCount * 4; // dwMsgs + dwErrors + types
            const int total = statsSize * 2;
            IntPtr buf = Marshal.AllocHGlobal(total);
            try
            {
                for (int i = 0; i < total; i++) Marshal.WriteByte(buf, i, 0);
                uint err = GetIcmpStatisticsEx(buf, family);
                if (err != 0) return;

                int inBase = 8;
                int outBase = statsSize + 8;
                if (v4)
                {
                    s.InEcho += ReadType(buf, inBase, V4Echo) + ReadType(buf, inBase, V4EchoReply);
                    s.OutEcho += ReadType(buf, outBase, V4Echo) + ReadType(buf, outBase, V4EchoReply);
                    s.InUnreach += ReadType(buf, inBase, V4Unreach);
                    s.InRedirect += ReadType(buf, inBase, V4Redirect);
                }
                else
                {
                    s.InEcho += ReadType(buf, inBase, V6Echo) + ReadType(buf, inBase, V6EchoReply);
                    s.OutEcho += ReadType(buf, outBase, V6Echo) + ReadType(buf, outBase, V6EchoReply);
                    s.InUnreach += ReadType(buf, inBase, V6Unreach);
                    s.InRedirect += ReadType(buf, inBase, V6Redirect);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static uint ReadType(IntPtr buf, int typeArrayOffset, int icmpType) =>
            (uint)Marshal.ReadInt32(buf, typeArrayOffset + icmpType * 4);

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIcmpStatisticsEx(IntPtr statistics, uint family);
    }

    internal static class NativeIpStats
    {
        public static uint InUnknownProtos()
        {
            const int size = 128;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                for (int i = 0; i < size; i++) Marshal.WriteByte(buf, i, 0);
                uint err = GetIpStatisticsEx(buf, 2);
                if (err != 0) return 0;
                return (uint)Marshal.ReadInt32(buf, 24);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        [DllImport("iphlpapi.dll")]
        private static extern uint GetIpStatisticsEx(IntPtr statistics, uint family);
    }

    internal static class FwpmNative
    {
        public const uint RpcCAuthnWinnt = 10;

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate void NetEventCallback(IntPtr context, IntPtr netEvent);

        [StructLayout(LayoutKind.Sequential)]
        public struct FWPM_NET_EVENT_SUBSCRIPTION0
        {
            public IntPtr enumTemplate;
            public uint flags;
            public Guid sessionKey;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FWP_VALUE0
        {
            public uint type;
            public uint pad;
            public uint uint32;
            public uint pad2;
        }

        public struct ParsedNetEvent
        {
            public byte IpProtocol;
            public int EventType;
            public int Pid;
            public int LocalPort;
            public int RemotePort;
            public string LocalAddress;
            public string RemoteAddress;
            public string AppPath;
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        public static extern uint FwpmEngineOpen0(
            string? serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmNetEventSubscribe0(
            IntPtr engineHandle,
            ref FWPM_NET_EVENT_SUBSCRIPTION0 subscription,
            IntPtr callback,
            IntPtr context,
            out IntPtr eventsHandle);

        [DllImport("fwpuclnt.dll")]
        public static extern uint FwpmNetEventUnsubscribe0(IntPtr engineHandle, IntPtr eventsHandle);

        [DllImport("fwpuclnt.dll")]
        private static extern uint FwpmEngineSetOption0(IntPtr engineHandle, uint option, ref FWP_VALUE0 newValue);

        public static void TryEnableNetEventCollection(IntPtr engine)
        {
            try
            {
                var value = new FWP_VALUE0 { type = 3, uint32 = 1 }; // FWP_UINT32 = 1
                FwpmEngineSetOption0(engine, 0, ref value); // FWPM_ENGINE_COLLECT_NET_EVENTS
            }
            catch { /* optional; subscribe may still receive drops */ }
        }

        /// <summary>
        /// Best-effort parse of FWPM_NET_EVENT0/1 header. Layout is documented in fwpmu.h;
        /// offsets are x64. Fail closed (return false) if the pointer is too small to trust.
        /// </summary>
        public static bool TryParseHeader(IntPtr netEvent, out ParsedNetEvent parsed)
        {
            parsed = default;
            try
            {
                // HEADER0 (x64, fwpmu.h):
                // 0 FILETIME(8)  8 flags(4)  12 ipVersion(4)  16 ipProtocol(1)
                // 20 localAddr(16)  36 remoteAddr(16)  52 localPort(2)  54 remotePort(2)
                // 56 scopeId(4)  64 appId.size(4)  72 appId.data(8)  80 userId(8)
                // 88 type(4)
                parsed.IpProtocol = Marshal.ReadByte(netEvent, 16);
                parsed.EventType = Marshal.ReadInt32(netEvent, 88);
                parsed.LocalPort = (ushort)Marshal.ReadInt16(netEvent, 52);
                parsed.RemotePort = (ushort)Marshal.ReadInt16(netEvent, 54);

                int ipVersion = Marshal.ReadInt32(netEvent, 12); // 0=V4, 1=V6
                parsed.LocalAddress = ReadAddr(netEvent, 20, ipVersion);
                parsed.RemoteAddress = ReadAddr(netEvent, 36, ipVersion);

                int blobSize = Marshal.ReadInt32(netEvent, 64);
                IntPtr blobData = Marshal.ReadIntPtr(netEvent, 72);
                parsed.AppPath = ReadAppId(blobData, blobSize);
                parsed.Pid = 0;
                if (!string.IsNullOrEmpty(parsed.AppPath))
                {
                    // appId is a path; PID is not in HEADER0. Leave 0 unless we can match later.
                    parsed.Pid = 0;
                }

                return parsed.EventType >= 0 && parsed.EventType <= 16;
            }
            catch
            {
                parsed = default;
                return false;
            }
        }

        private static string ReadAddr(IntPtr p, int offset, int ipVersion)
        {
            try
            {
                if (ipVersion == 0)
                {
                    uint v = (uint)Marshal.ReadInt32(p, offset);
                    return new IPAddress(BitConverter.GetBytes(v)).ToString();
                }
                var b = new byte[16];
                Marshal.Copy(IntPtr.Add(p, offset), b, 0, 16);
                return new IPAddress(b).ToString();
            }
            catch { return ""; }
        }

        private static string ReadAppId(IntPtr data, int size)
        {
            if (data == IntPtr.Zero || size <= 2 || size > 4096) return "";
            try
            {
                var bytes = new byte[size];
                Marshal.Copy(data, bytes, 0, size);
                var s = Encoding.Unicode.GetString(bytes).TrimEnd('\0');
                if (s.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase) ||
                    s.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
                {
                    int slash = s.LastIndexOf('\\');
                    if (slash >= 0 && slash < s.Length - 1)
                        return s;
                }
                return s;
            }
            catch { return ""; }
        }
    }

    internal static class ProtocolEmitMeta
    {
        public static Dictionary<string, string> Create(string? path, string endpoint, int port, bool weak, string protocol)
        {
            var d = new Dictionary<string, string>
            {
                ["Protocol"] = protocol,
                ["Port"] = port.ToString(),
                ["Endpoint"] = endpoint ?? "",
            };
            if (!string.IsNullOrEmpty(path)) d["ImagePath"] = path!;
            if (weak) d["WeakObserveSeed"] = "true";
            return d;
        }
    }
}
