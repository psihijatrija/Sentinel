using System;
using System.Diagnostics;
using System.IO;

namespace NanoAV
{
    internal static class Program
    {
        [STAThread]
        private static void Main(string[] args)
        {
            Console.WriteLine("NanoAV Lite - Installation");
            Console.WriteLine();

            string dllPath = Path.Combine(Config.BaseDirectory, "NanoAV.dll");
            
            // Install if not installed
            bool installed = false;
            if (!File.Exists(dllPath) || !File.Exists(Path.Combine(Config.BaseDirectory, ".installed")))
            {
                if (!IsAdministrator())
                {
                    RelaunchAsAdmin();
                    return;
                }

                if (!Install())
                {
                    Console.WriteLine("Installation failed.");
                    return;
                }
                installed = true;
            }

            // Always start the COM server monitoring
            NanoAVComServer.Start();
            
            if (installed)
            {
                Console.WriteLine("NanoAV Lite installed and COM Server started.");
            }
            else
            {
                Console.WriteLine("NanoAV Lite already installed. COM Server started.");
            }
        }

        private static bool Install()
        {
            try
            {
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                string dllPath = Path.Combine(Config.BaseDirectory, "NanoAV.dll");

                Directory.CreateDirectory(Config.BaseDirectory);
                File.Copy(exePath, dllPath, overwrite: true);

                Logger.Log("=== NanoAV Lite Installation ===");
                Logger.Log("Installing DLL: " + dllPath);

                File.WriteAllText(Path.Combine(Config.BaseDirectory, ".installed"), 
                    "NanoAV Lite installed on " + DateTime.Now.ToString("o"));

                // Register COM server using regasm
                RegisterWithRegasm(dllPath);
                
                Logger.Log("Installation completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                Logger.Log("Installation failed: " + ex.Message);
                return false;
            }
        }

        private static void RegisterWithRegasm(string dllPath)
        {
            try
            {
                // Find regasm - try 64-bit first, then 32-bit
                string regasmPath = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe";
                if (!File.Exists(regasmPath))
                {
                    regasmPath = @"C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe";
                }

                if (!File.Exists(regasmPath))
                {
                    Logger.Log("regasm.exe not found. Cannot register COM server properly.");
                    return;
                }

                // Register the COM server with /codebase flag
                ProcessHelper.Run(regasmPath, "\"" + dllPath + "\" /codebase /silent");
                
                // Register Run key to run the EXE (which installs and starts COM server)
                string exePath = Process.GetCurrentProcess().MainModule.FileName;
                using (var runKey = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    runKey.SetValue("NanoAV", "\"" + exePath + "\"");
                }

                Logger.Log("COM Server registered via regasm. Run key entry created for EXE.");
            }
            catch (Exception ex)
            {
                Logger.Log("regasm registration failed: " + ex.Message);
            }
        }

        private static bool IsAdministrator()
        {
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        private static void RelaunchAsAdmin()
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    UseShellExecute = true,
                    WorkingDirectory = Environment.CurrentDirectory,
                    FileName = Process.GetCurrentProcess().MainModule.FileName,
                    Verb = "runas",
                    Arguments = ""
                };
                Process.Start(startInfo);
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to elevate: " + ex.Message);
                Console.WriteLine("Administrator rights required.");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                Environment.Exit(1);
            }
        }
    }
}
