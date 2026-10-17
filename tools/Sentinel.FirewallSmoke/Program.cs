using System;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using Sentinel.Core;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            // This host intentionally mutates machine firewall policy. It is a disposable CI fixture,
            // not a product administration command or a test to run on a developer's workstation.
            if (Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true"
                || Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows"
                || Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT") != "github-hosted")
                throw new InvalidOperationException("A disposable GitHub-hosted Windows runner is required");
            using (var identity = WindowsIdentity.GetCurrent())
                if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                    throw new UnauthorizedAccessException("An administrator token is required inside the disposable runner");
            if (args.Length < 2) throw new ArgumentException("Expected operation and fixture directory");
            var isolation = new SelfNetworkIsolation(new WindowsSelfNetworkFirewall(), args[1]);
            if (args[0] == "NativeApply" || args[0] == "NativeRemove")
            {
                if (args[0] == "NativeApply") isolation.Apply(); else isolation.Remove();
                Console.WriteLine(JsonSerializer.Serialize(new { Ok = true }));
            }
            else
                Console.WriteLine(new WindowsFirewallPolicyBridge(args[1]).RunAsync(args[0], CancellationToken.None,
                    args.Length > 2 ? args[2] : null, args.Length > 3 ? args[3] : null).GetAwaiter().GetResult());
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
}
