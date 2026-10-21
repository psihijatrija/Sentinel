// NanoAV - C# 5 / .NET 4.8 port of NanoAV.ps1
// Author: Gorstak (original PowerShell), ported to C#.
using System;
using System.Collections.Generic;
using System.IO;

namespace NanoAV
{
    // Central configuration, mirrors the $Config / $BehaviorConfig / $C2Config
    // hashtables from the original PowerShell script.
    internal static class Config
    {
        public const string BaseDirectory       = @"C:\ProgramData\NanoAV";
        public const string QuarantineDirectory = @"C:\ProgramData\NanoAV\Quarantine";
        public const string BackupDirectory     = @"C:\ProgramData\NanoAV\Backup";
        public const string LogFile             = @"C:\ProgramData\NanoAV\NanoAV.log";
        public const string BlockedLogFile      = @"C:\ProgramData\NanoAV\blocked.log";
        public const string DatabaseFile        = @"C:\ProgramData\NanoAV\known_files.db";
        public const string OwnPidFile          = @"C:\ProgramData\NanoAV\NanoAV_pids.txt";
        public static string RulesDirectory { get { return Path.Combine(BaseDirectory, "rules"); } }
        public static string MemoryHitsLog { get { return Path.Combine(BaseDirectory, "memory_hits.log"); } }

        public const int    MaxDatabaseEntries    = 50000;
        public const int    MaxLogSizeMB          = 10;
        public const int    MemoryScanIntervalSec = 300;
        public const int    MemoryScanMaxSizeMB   = 150;
        public const int    ProcessTimeoutSeconds = 30;
        public const int    DatabaseCleanupDays   = 30;

        public const bool   EnableMemoryScanning  = true;
        public const bool   EnableRealtimeMonitor = true;
        public const bool   EnableAutoStart       = true;
        public const string AutoStartTaskName     = "NanoAV";
        public const bool   EnableThreatIntel     = true;
        public const bool   EnableAlerts          = true;
        public const bool   AutoQuarantine        = true;

        public const string MalwareBazaarApiKey   = "";
        public const string CirclHashLookupUrl    = "https://hashlookup.circl.lu/lookup/sha256";
        public const string CymruApiUrl           = "https://api.malwarehash.cymru.com/v1/hash";
        public const string MalwareBazaarApiUrl   = "https://mb-api.abuse.ch/api/v1/";

        public const int    CymruDetectionThreshold = 60;
        public const int    SuspiciousFileSizeKB    = 3072;

        // --- BehaviorConfig ---
        public const bool EnableBehaviorKill    = true;
        public const bool EnableAutoBlockC2     = true;
        public const int  DeepScanIntervalHours = 6;
        public const int  ThreatIntelUpdateDays = 7;

        // --- C2Config ---
        public const bool EnableC2Detection       = true;
        public const bool EnableReverseShellKill  = true;
        public const bool EnableBeaconDetection   = true;
        public const bool EnableFirewallAutoBlock = true;
        public const int  KillScoreThreshold      = 50;
        public const int  FirewallBlockThreshold  = 40;
        public const int  BeaconMinSamples        = 4;
        public const double BeaconMaxJitterRatio  = 0.25;
        public const int  BeaconMinIntervalSec    = 10;
        public const int  BeaconMaxIntervalSec    = 86400;
        public const int  IpRotationThreshold     = 12;

        // Ports strongly associated with Metasploit/backdoors/reverse shells.
        public static readonly Dictionary<int, int> C2SuspiciousPorts = new Dictionary<int, int>
        {
            {4444,30},{4445,30},{5555,30},{6666,20},{7777,20},{8888,15},
            {9001,20},{9002,20},{9999,15},{1337,25},{31337,25},
            {12345,20},{54321,20},{50050,35}
        };

        public static readonly string[] C2MaliciousRangePrefixes =
            { "5.8.", "45.", "91.", "185.", "194.", "195." };

        public static readonly string[] C2SuspiciousTLDs =
            { ".onion", ".bit", ".i2p", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
              ".xyz", ".duckdns.org", ".ddns.net", ".no-ip.org", ".hopto.org" };

        public static readonly string[] C2SuspiciousProcesses =
            { "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32",
              "regsvr32", "certutil", "bitsadmin", "installutil", "msbuild" };

        // Reverse-shell command-line signatures (regex, case-insensitive).
        public static readonly string[] ReverseShellPatterns =
        {
            @"powershell.*-nop.*-w.*hidden.*-(e|enc|encodedcommand)",
            @"powershell.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}",
            @"new-object\s+system\.net\.sockets\.tcpclient",
            @"new-object\s+net\.sockets\.tcpclient",
            @"\$client\s*=\s*new-object.*tcpclient",
            @"getstream\(\).*\.read\(|\.write\(.*getstream",
            @"iex\s*\(.*\.getstream",
            @"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+",
            @"bash\s+-i\s+>&\s*/dev/tcp",
            @"sh\s+-i\s+2>&1",
            @"\bnc(\.exe)?\b.*(-e|-c)\s+(cmd|/bin/sh|bash|powershell)",
            @"\bncat(\.exe)?\b.*(-e|--exec)",
            @"\bsocat\b.*exec",
            @"cmd(\.exe)?\s+/c\s+.*(nc|ncat|socat|telnet)\b",
            @"python.*socket.*connect.*subprocess.*(call|popen)",
            @"perl.*socket.*(exec|system)\(",
            @"php\s+-r.*fsockopen"
        };

        public static readonly string[] AllowedSIDs = { "S-1-2-0", "S-1-5-20" };

        public static readonly string[] RiskyPaths =
            { @"\temp\", @"\downloads\", @"\appdata\local\temp\", @"\public\",
              @"\windows\temp\", @"\appdata\roaming\", @"\desktop\" };

        public static readonly HashSet<string> ProtectedProcesses = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            "System","Idle","Registry","smss","csrss","wininit","services","lsass",
            "svchost","winlogon","explorer","dwm","SearchUI","SearchIndexer","fontdrvhost",
            "RuntimeBroker","sihost","taskhostw"
        };

        public static readonly string[] EvilStrings =
        {
            "mimikatz","sekurlsa::","kerberos::","lsadump::","wdigest","tspkg",
            "http-beacon","https-beacon","cobaltstrike","sleepmask","reflective",
            "amsi.dll","AmsiScanBuffer","EtwEventWrite","MiniDumpWriteDump",
            "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread",
            "ReflectiveLoader","sharpchrome","rubeus","safetykatz","sharphound",
            "invoke-mimikatz","invoke-bloodhound","powersploit","empire"
        };

        // Monitored extensions (full list from the original script).
        public static readonly HashSet<string> MonitoredExtensions = new HashSet<string>(
            StringComparer.OrdinalIgnoreCase)
        {
            ".exe",".dll",".sys",".ocx",".scr",".com",".cpl",".msi",".drv",".winmd",
            ".ps1",".bat",".cmd",".vbs",".js",".hta",".jse",".wsf",".wsh",".psc1",".exif",
            ".zoo",".zlo",".zfsendtotarget",".z",".xz",".xsl",".xps",".xpi",".xnk",".xml",
            ".xlw",".xltx",".xltm",".xlt",".xlsx",".xlsm",".xlsb",".xls",".xlm",".xll",
            ".xld",".xlc",".xlb",".xlam",".xla",".xip",".xbap",".xar",".wwl",".wsc",
            ".ws",".wll",".wiz",".website",".webpnp",".webloc",".wbk",".was",".vxd",
            ".vsw",".vst",".vss",".vsmacros",".vhdx",".vhd",".vbp",".vb",".url",".tz",
            ".txz",".tsp",".tpz",".tool",".tmp",".tlb",".theme",".tgz",".terminal",
            ".term",".tbz",".taz",".tar",".swf",".stm",".spl",".slk",".sldx",
            ".sldm",".sit",".shs",".shb",".settingcontent-ms",".search-ms",".searchconnector-ms",
            ".sea",".sct",".scf",".rtf",".rqy",".rpy",".rev",".reg",".rb",
            ".rar",".r09",".r08",".r07",".r06",".r05",".r04",".r03",".r02",".r01",
            ".r00",".pyzw",".pyz",".pyx",".pywz",".pyw",".pyt",".pyp",".pyo",".pyi",
            ".pyde",".pyd",".pyc",".py3",".py",".pxd",".pstreg",".pst",".psdm1",".psd1",
            ".prn",".printerexport",".prg",".prf",".pptx",".pptm",".ppt",".ppsx",".ppsm",
            ".pps",".ppam",".ppa",".potx",".potm",".pot",".plg",".pl",".pkg",".pif",
            ".pi",".perl",".pcd",".pa",".osd",".oqy",".ops",".one",".ods",
            ".ntfs",".nsh",".nls",".mydocs",".mui",".msu",".mst",".msp",".mshxml",
            ".msh2xml",".msh2",".msh1xml",".msh1",".msh",".mof",".mmc",".mhtml",".mht",
            ".mdz",".mdw",".mdt",".mdn",".mdf",".mde",".mdb",".mda",".mcl",".mcf",
            ".may",".maw",".mNanoAV",".mau",".mat",".mas",".mar",".maq",".mapimail",
            ".manifest",".mam",".mag",".maf",".mad",".lzh",".local",".library-ms",
            ".lha",".ldb",".laccdb",".ksh",".job",".jnlp",".jar",".its",".isp",".iso",
            ".iqy",".ins",".ini",".inf",".img",".ime",".ie",".hwp",".htt",".htm",
            ".htc",".hpj",".hlp",".hex",".gz",".grp",".glk",".gadget",
            ".fxp",".fon",".fat",".elf",".ecf",".dqy",".dotx",".dotm",
            ".dot",".docm",".docb",".doc",".dmg",".dir",".dif",".diagcab",
            ".desktop",".desklink",".der",".dcr",".db",".csv",".csh",".crx",".crt",
            ".crazy",".cpx",".command",".cnt",".cnv",".clb",
            ".class",".cla",".chm",".chi",".cfg",".cer",".cdb",".cab",".bzip2",".bzip",
            ".bz2",".bz",".bas",".ax",".asx",".aspx",".asp",".asa",".arj",
            ".arc",".appref-ms",".application",".app",".air",".adp",".adn",".ade",
            ".ad",".acm",".accdu",".accdt",".accdr",".accde",".accda",".c",".h"
        };
    }
}
