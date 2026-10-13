// =============================================================================
// Sentinel.AutoRotate (SentinelAutoRotate.exe)
//
// WHAT THIS TOOL DOES - honestly:
//   It keeps a single local Windows account's password UNKNOWN to any human
//   while still allowing that account to log in, install, and run software.
//   It does this by rotating the account password to a fresh strong random
//   value every 10 minutes (via a SYSTEM scheduled task) and keeping Windows
//   autologon enabled so that power-on lands directly at the desktop. The
//   password is NEVER blanked - it is always a >=20 char cryptographically
//   random string.
//
// SECURITY TRADEOFF - read before deploying:
//   To make autologon work, the current password must be stored where Winlogon
//   can read it at boot: the LSA private secret "DefaultPassword" (stored via
//   LsaStorePrivateData, NOT the cleartext DefaultPassword registry value).
//   That secret is machine-recoverable: ANY process running as SYSTEM or local
//   admin can read it back in cleartext (LsaRetrievePrivateData, or an LSASS
//   dump). So this tool:
//     - DEFENDS against: humans learning the password, interactive logon
//       guessing/brute force, credential phishing, and password reuse across
//       machines (every box has a different, constantly-changing secret).
//     - Does NOT defend against: an attacker who ALREADY has local admin /
//       SYSTEM on this machine - they can recover the current password.
//   It is a human-knowledge and remote-guessing control, not an anti-admin
//   control. It also sets UAC ConsentPromptBehaviorAdmin=5 so admins still get
//   a consent prompt (not silent elevation) when installing software.
//
//   This tool is intentionally and completely decoupled from the Sentinel EDR:
//   no project reference in either direction, no DI, no MonitorGroup, no
//   detection registration. It is an installer-style standalone utility.
//
// MODES:
//   --install    (admin) register SYSTEM scheduled tasks (startup + every 10
//                min) that invoke "--rotate", enable autologon for the target
//                account, and set UAC ConsentPromptBehaviorAdmin=5.
//   --rotate     (SYSTEM) generate a strong random password, apply it to the
//                target local account, and refresh autologon so the next boot
//                still logs in. Never blanks, never logs the password.
//   --uninstall  delete the scheduled tasks and disable autologon (remove the
//                LSA DefaultPassword secret). The account is LEFT on its last
//                random password - it is not blanked.
// =============================================================================

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace Sentinel.AutoRotate;

internal static class Program
{
    // Fallback local account used when no interactive console user can be
    // determined (e.g. --rotate fires before anyone has logged in). This is the
    // account whose password is rotated and auto-logged-on.
    private const string FallbackAccountName = "Sentinel";

    // Scheduled task names created by --install / removed by --uninstall.
    private const string TaskNameStartup = "SentinelAutoRotateStartup";
    private const string TaskNameRecurring = "SentinelAutoRotate";

    private const string WinlogonKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
    private const string UacPolicyKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

    private const int MinPasswordLength = 24;

    private static int Main(string[] args)
    {
        string mode = args.Length > 0 ? args[0].Trim().ToLowerInvariant() : string.Empty;

        return mode switch
        {
            "--install" => RunGuarded(Install),
            "--rotate" => RunGuarded(Rotate),
            "--uninstall" => RunGuarded(Uninstall),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.Error.WriteLine(
            "SentinelAutoRotate - rotates a local account password every 10 minutes while keeping autologon.\n" +
            "Usage:\n" +
            "  SentinelAutoRotate.exe --install     Register SYSTEM tasks, enable autologon, set UAC=5 (requires admin).\n" +
            "  SentinelAutoRotate.exe --rotate      Rotate the password now and refresh autologon (runs as SYSTEM).\n" +
            "  SentinelAutoRotate.exe --uninstall   Remove tasks and disable autologon (password is left random, not blanked).");
        return 2;
    }

    // Wrap a mode in a try/catch: every failure is logged and returns nonzero.
    private static int RunGuarded(Func<int> mode)
    {
        try
        {
            return mode();
        }
        catch (Exception ex)
        {
            Log("ERROR: unhandled exception: " + ex);
            return 1;
        }
    }

    // ---- --install ----------------------------------------------------------

    private static int Install()
    {
        if (!IsAdministrator())
        {
            Log("ERROR: --install requires administrator privileges.");
            Console.Error.WriteLine("--install must be run as administrator.");
            return 1;
        }

        string exePath = GetExecutablePath();
        string account = ResolveTargetAccount();
        Log($"Install: exe='{exePath}', target account='{account}'.");

        // (a) Register SYSTEM scheduled tasks idempotently (delete then create).
        //     schtasks.exe is permitted here (standalone installer-style tool).
        int rc = RegisterTasks(exePath);
        if (rc != 0)
        {
            Log($"ERROR: scheduled task registration failed (rc={rc}).");
            return rc;
        }

        // (b) Enable autologon for the target account. The password secret is
        //     written by the first --rotate; here we set the account/flags.
        EnableAutologon(account);

        // (c) Set UAC ConsentPromptBehaviorAdmin=5 (prompt for consent on secure
        //     desktop) via the registry directly - no shelling out.
        SetUacConsentPrompt(5);

        Log("Install: completed.");
        Console.Out.WriteLine("SentinelAutoRotate installed. Run --rotate once (or reboot) to set the first random password.");
        return 0;
    }

    private static int RegisterTasks(string exePath)
    {
        // Delete any prior instances first (ignore failures: may not exist).
        RunSchtasks($"/Delete /TN \"{TaskNameStartup}\" /F");
        RunSchtasks($"/Delete /TN \"{TaskNameRecurring}\" /F");

        string tr = $"\"{exePath}\" --rotate";

        // Startup trigger: rotate once at boot (as SYSTEM).
        int rc1 = RunSchtasks(
            $"/Create /TN \"{TaskNameStartup}\" /TR \"{tr}\" /SC ONSTART /RU SYSTEM /RL HIGHEST /F");
        if (rc1 != 0)
        {
            return rc1;
        }

        // Recurring trigger: rotate every 10 minutes indefinitely (as SYSTEM).
        int rc2 = RunSchtasks(
            $"/Create /TN \"{TaskNameRecurring}\" /TR \"{tr}\" /SC MINUTE /MO 10 /RU SYSTEM /RL HIGHEST /F");
        return rc2;
    }

    private static int RunSchtasks(string arguments)
    {
        var psi = new System.Diagnostics.ProcessStartInfo
        {
            FileName = "schtasks.exe",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var p = System.Diagnostics.Process.Start(psi);
        if (p is null)
        {
            Log("ERROR: failed to start schtasks.exe.");
            return 1;
        }

        string stdout = p.StandardOutput.ReadToEnd();
        string stderr = p.StandardError.ReadToEnd();
        p.WaitForExit();

        Log($"schtasks {arguments} -> exit {p.ExitCode}. " +
            $"out='{stdout.Trim()}' err='{stderr.Trim()}'");
        return p.ExitCode;
    }

    // ---- --rotate -----------------------------------------------------------

    private static int Rotate()
    {
        string account = ResolveTargetAccount();
        Log($"Rotate: target account='{account}'.");

        // Generate a strong random password (never System.Random, never empty).
        string password = GeneratePassword(MinPasswordLength);

        // Apply to the local account via NetUserSetInfo level 1003.
        var info = new NativeMethods.USER_INFO_1003 { usri1003_password = password };
        uint result = NativeMethods.NetUserSetInfo(null, account, 1003, ref info, out uint parmErr);
        if (result != NativeMethods.NERR_Success)
        {
            Log($"ERROR: NetUserSetInfo failed for '{account}' (result={result}, parmErr={parmErr}).");
            return 1;
        }

        Log($"Rotate: password updated for '{account}'.");

        // Refresh autologon so the next boot still logs in with the new secret.
        EnableAutologon(account);
        StoreAutologonSecret(password);

        // Scrub local reference ASAP (best effort; strings are immutable in .NET).
        password = string.Empty;

        Log("Rotate: completed.");
        return 0;
    }

    // ---- --uninstall --------------------------------------------------------

    private static int Uninstall()
    {
        Log("Uninstall: starting.");

        RunSchtasks($"/Delete /TN \"{TaskNameStartup}\" /F");
        RunSchtasks($"/Delete /TN \"{TaskNameRecurring}\" /F");

        // Disable autologon and remove the LSA DefaultPassword secret.
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true);
            if (key is not null)
            {
                key.SetValue("AutoAdminLogon", "0", RegistryValueKind.String);
            }
        }
        catch (Exception ex)
        {
            Log("ERROR: failed to clear AutoAdminLogon: " + ex);
            return 1;
        }

        RemoveAutologonSecret();

        Log("Uninstall: completed.");
        Console.Out.WriteLine(
            "SentinelAutoRotate removed. The account password is still a random value and was NOT blanked. " +
            "Reset it with standard Windows tools (e.g. 'Computer Management > Local Users and Groups', " +
            "or 'net user <name> *') to regain a known password.");
        return 0;
    }

    // ---- autologon helpers --------------------------------------------------

    private static void EnableAutologon(string account)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(WinlogonKey, writable: true);
        if (key is null)
        {
            Log("ERROR: unable to open Winlogon registry key.");
            return;
        }

        key.SetValue("AutoAdminLogon", "1", RegistryValueKind.String);
        key.SetValue("DefaultUserName", account, RegistryValueKind.String);
        key.SetValue("DefaultDomainName", Environment.MachineName, RegistryValueKind.String);

        // Ensure the cleartext DefaultPassword registry value is NOT present;
        // the password lives only in the LSA secret.
        if (key.GetValue("DefaultPassword") is not null)
        {
            key.DeleteValue("DefaultPassword", throwOnMissingValue: false);
        }

        Log($"Autologon enabled for '{account}' on domain '{Environment.MachineName}'.");
    }

    private static void SetUacConsentPrompt(int value)
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(UacPolicyKey, writable: true);
        if (key is null)
        {
            Log("ERROR: unable to open UAC policy registry key.");
            return;
        }

        key.SetValue("ConsentPromptBehaviorAdmin", value, RegistryValueKind.DWord);
        Log($"UAC ConsentPromptBehaviorAdmin set to {value}.");
    }

    // Store the password as the LSA private secret "DefaultPassword" so Winlogon
    // can perform autologon at boot. This is the machine-recoverable secret
    // documented in the header - never the cleartext registry value.
    private static void StoreAutologonSecret(string password)
    {
        WriteLsaSecret("DefaultPassword", password);
        Log("Autologon LSA secret stored.");
    }

    private static void RemoveAutologonSecret()
    {
        WriteLsaSecret("DefaultPassword", null);
        Log("Autologon LSA secret removed.");
    }

    // value == null => delete the secret.
    private static void WriteLsaSecret(string keyName, string? value)
    {
        var objectAttributes = new NativeMethods.LSA_OBJECT_ATTRIBUTES
        {
            Length = Marshal.SizeOf<NativeMethods.LSA_OBJECT_ATTRIBUTES>(),
        };

        uint status = NativeMethods.LsaOpenPolicy(
            IntPtr.Zero,
            ref objectAttributes,
            NativeMethods.POLICY_CREATE_SECRET,
            out IntPtr policyHandle);

        if (status != 0)
        {
            int win = NativeMethods.LsaNtStatusToWinError(status);
            Log($"ERROR: LsaOpenPolicy failed (NTSTATUS=0x{status:X8}, win32={win}).");
            throw new InvalidOperationException($"LsaOpenPolicy failed (win32={win}).");
        }

        LSA_UNICODE_STRING_Pair key = default;
        LSA_UNICODE_STRING_Pair data = default;
        IntPtr dataPtr = IntPtr.Zero;

        try
        {
            key = AllocLsaString(keyName);
            NativeMethods.LSA_UNICODE_STRING keyName_native = key.Native;

            if (value is null)
            {
                // Null PrivateData deletes the secret.
                status = NativeMethods.LsaStorePrivateData(policyHandle, ref keyName_native, IntPtr.Zero);
            }
            else
            {
                data = AllocLsaString(value);
                dataPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.LSA_UNICODE_STRING>());
                Marshal.StructureToPtr(data.Native, dataPtr, fDeleteOld: false);
                status = NativeMethods.LsaStorePrivateData(policyHandle, ref keyName_native, dataPtr);
            }

            if (status != 0)
            {
                int win = NativeMethods.LsaNtStatusToWinError(status);
                Log($"ERROR: LsaStorePrivateData failed (NTSTATUS=0x{status:X8}, win32={win}).");
                throw new InvalidOperationException($"LsaStorePrivateData failed (win32={win}).");
            }
        }
        finally
        {
            if (dataPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(dataPtr);
            }

            FreeLsaString(data);
            FreeLsaString(key);
            NativeMethods.LsaClose(policyHandle);
        }
    }

    private readonly struct LSA_UNICODE_STRING_Pair
    {
        public LSA_UNICODE_STRING_Pair(NativeMethods.LSA_UNICODE_STRING native, IntPtr buffer)
        {
            Native = native;
            Buffer = buffer;
        }

        public NativeMethods.LSA_UNICODE_STRING Native { get; }
        public IntPtr Buffer { get; }
    }

    private static LSA_UNICODE_STRING_Pair AllocLsaString(string s)
    {
        // Length/MaximumLength are in BYTES. MaximumLength includes the
        // terminating null; Length excludes it.
        IntPtr buffer = Marshal.StringToHGlobalUni(s);
        var native = new NativeMethods.LSA_UNICODE_STRING
        {
            Length = (ushort)(s.Length * sizeof(char)),
            MaximumLength = (ushort)((s.Length + 1) * sizeof(char)),
            Buffer = buffer,
        };
        return new LSA_UNICODE_STRING_Pair(native, buffer);
    }

    private static void FreeLsaString(LSA_UNICODE_STRING_Pair pair)
    {
        if (pair.Buffer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(pair.Buffer);
        }
    }

    // ---- target account resolution -----------------------------------------

    // Prefer the interactive console user; fall back to the configured constant.
    private static string ResolveTargetAccount()
    {
        try
        {
            uint sessionId = NativeMethods.WTSGetActiveConsoleSessionId();
            if (sessionId != 0xFFFFFFFF &&
                NativeMethods.WTSQuerySessionInformation(
                    (IntPtr)NativeMethods.WTS_CURRENT_SERVER_HANDLE,
                    sessionId,
                    NativeMethods.WTS_INFO_CLASS.WTSUserName,
                    out IntPtr buffer,
                    out _))
            {
                try
                {
                    string? user = Marshal.PtrToStringUni(buffer);
                    if (!string.IsNullOrWhiteSpace(user))
                    {
                        return user!;
                    }
                }
                finally
                {
                    NativeMethods.WTSFreeMemory(buffer);
                }
            }
        }
        catch (Exception ex)
        {
            Log("WARN: could not resolve console session user, using fallback: " + ex.Message);
        }

        return FallbackAccountName;
    }

    // ---- password generation ------------------------------------------------

    // Cryptographically strong, >= length, guaranteed upper+lower+digit+symbol.
    private static string GeneratePassword(int length)
    {
        if (length < 4)
        {
            length = 4;
        }

        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string lower = "abcdefghijkmnpqrstuvwxyz";
        const string digits = "23456789";
        const string symbols = "!@#$%^&*()-_=+[]{}";
        string all = upper + lower + digits + symbols;

        var chars = new char[length];

        // Guarantee one of each required class.
        chars[0] = PickChar(upper);
        chars[1] = PickChar(lower);
        chars[2] = PickChar(digits);
        chars[3] = PickChar(symbols);

        for (int i = 4; i < length; i++)
        {
            chars[i] = PickChar(all);
        }

        // Fisher-Yates shuffle with crypto randomness so the guaranteed chars
        // are not always in the first four positions.
        for (int i = length - 1; i > 0; i--)
        {
            int j = NextInt(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }

    private static char PickChar(string set) => set[NextInt(set.Length)];

    // Unbiased random int in [0, maxExclusive) using RandomNumberGenerator.
    private static int NextInt(int maxExclusive)
    {
        if (maxExclusive <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxExclusive));
        }

        uint limit = (uint)(0x100000000UL - (0x100000000UL % (ulong)maxExclusive));
        var bytes = new byte[4];
        uint value;
        using var rng = RandomNumberGenerator.Create();
        do
        {
            rng.GetBytes(bytes);
            value = BitConverter.ToUInt32(bytes, 0);
        }
        while (value >= limit);

        return (int)(value % (uint)maxExclusive);
    }

    // ---- misc ---------------------------------------------------------------

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string GetExecutablePath()
    {
        string? path = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
        if (!string.IsNullOrEmpty(path))
        {
            return path!;
        }

        return AppContext.BaseDirectory;
    }

    private static readonly object LogLock = new();

    private static void Log(string message)
    {
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Sentinel", "AutoRotate");
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, "autorotate.log");
            string line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {message}{Environment.NewLine}";

            lock (LogLock)
            {
                File.AppendAllText(file, line);
            }
        }
        catch
        {
            // Logging must never throw out of a mode handler.
        }
    }
}
