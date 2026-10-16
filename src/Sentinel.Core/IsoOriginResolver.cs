using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;

namespace Sentinel.Core
{
    public static class IsoOriginResolver
    {
        /// <summary>
        /// True when the given process image path lives on a mounted CD-ROM / ISO volume.
        /// A CD-ROM-typed volume in a userland context is, in practice, a mounted disk image
        /// (physical optical drives are essentially extinct on the target systems). Fail-closed
        /// false on any error.
        /// </summary>
        public static bool IsImagePathOnMountedIso(string? imagePath)
        {
            if (string.IsNullOrEmpty(imagePath)) return false;
            try
            {
                var root = Path.GetPathRoot(imagePath); // e.g. "E:\"
                if (string.IsNullOrEmpty(root)) return false;
                var di = new DriveInfo(root!);
                return di.DriveType == DriveType.CDRom;
            }
            catch { return false; }
        }

        /// <summary>
        /// Resolves the .iso (or other disk-image) file backing a mounted CD-ROM/virtual volume,
        /// given a drive letter like "E" or "E:" or "E:\". Uses the Storage WMI namespace
        /// (root\Microsoft\Windows\Storage : MSFT_DiskImage) which records the ImagePath of every
        /// mounted disk image. Returns null if the drive is not a mounted image or cannot be
        /// resolved. Read-only.
        /// </summary>
        public static string? ResolveBackingImagePath(string? driveLetter)
        {
            var letter = NormalizeLetter(driveLetter);
            if (letter == null) return null;

            // Primary: MSFT_DiskImage in the Storage namespace exposes ImagePath + DevicePath and,
            // via MSFT_Volume association, the mounted drive letter. We match by drive letter.
            try
            {
                var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
                scope.Connect();

                // Enumerate mounted disk images and correlate each to its volume's drive letter.
                using var searcher = new ManagementObjectSearcher(
                    scope, new ObjectQuery("SELECT ImagePath, DevicePath, StorageType FROM MSFT_DiskImage"));
                foreach (ManagementObject image in searcher.Get())
                {
                    var imagePath = image["ImagePath"]?.ToString();
                    if (string.IsNullOrEmpty(imagePath)) continue;

                    if (DiskImageIsMountedAtLetter(scope, image, letter))
                        return imagePath;
                }
            }
            catch
            {
                // Storage namespace may be unavailable (down-level / restricted) - fall through.
            }

            return null;
        }

        /// <summary>
        /// Enumerates processes whose main image path resides on the given mounted ISO/CD-ROM
        /// drive letter. These are the candidate "ISO-hosted" processes for containment.
        /// Read-only; returns an empty list on failure.
        /// </summary>
        public static IReadOnlyList<int> EnumerateProcessesRunningFromDrive(string? driveLetter)
        {
            var letter = NormalizeLetter(driveLetter);
            var pids = new List<int>();
            if (letter == null) return pids;

            var prefix = letter + ":\\";
            foreach (var proc in SafeGetProcesses())
            {
                try
                {
                    var img = SecurityValidation.GetProcessImagePath(proc.Id);
                    if (!string.IsNullOrEmpty(img) &&
                        img!.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    {
                        pids.Add(proc.Id);
                    }
                }
                catch { }
                finally { try { proc.Dispose(); } catch { } }
            }
            return pids;
        }

        /// <summary>
        /// Given a process id, returns the backing .iso path if that process runs from a mounted
        /// disk image, else null. This is the exact input contract for HandleIsoThreatAsync.
        /// </summary>
        public static string? ResolveBackingImageForProcess(int processId)
        {
            if (processId <= 4) return null;
            try
            {
                var img = SecurityValidation.GetProcessImagePath(processId);
                if (!IsImagePathOnMountedIso(img)) return null;
                var root = Path.GetPathRoot(img!); // "E:\"
                var letter = NormalizeLetter(root);
                return ResolveBackingImagePath(letter);
            }
            catch { return null; }
        }

        // -----------------------------------------------------------------------------------
        private static bool DiskImageIsMountedAtLetter(ManagementScope scope, ManagementObject image, string letter)
        {
            try
            {
                // MSFT_DiskImage -> MSFT_Disk (ASSOCIATORS) -> MSFT_Partition -> MSFT_Volume.DriveLetter
                // The Storage model associations are verbose; the robust, cheap correlation is to
                // compare the image's DevicePath-derived disk number against the volume carrying
                // our drive letter. We use the simpler DriveLetter property exposed on the
                // associated MSFT_Volume via ASSOCIATORS.
                var path = image.Path.Path; // full __PATH of the MSFT_DiskImage instance
                using var assoc = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery(
                        $"ASSOCIATORS OF {{{path}}} WHERE ResultClass=MSFT_Volume"));
                foreach (ManagementObject vol in assoc.Get())
                {
                    var dl = vol["DriveLetter"];
                    if (dl == null) continue;
                    // DriveLetter is a char (uint16) in the Storage model.
                    var dlStr = dl.ToString();
                    if (!string.IsNullOrEmpty(dlStr) &&
                        dlStr!.TrimEnd(':', '\\').Equals(letter, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
            catch { }
            return false;
        }

        private static string? NormalizeLetter(string? driveLetter)
        {
            if (string.IsNullOrWhiteSpace(driveLetter)) return null;
            var s = driveLetter!.Trim().TrimEnd('\\').TrimEnd(':');
            if (s.Length != 1 || !char.IsLetter(s[0])) return null;
            return s.ToUpperInvariant();
        }

        private static IEnumerable<Process> SafeGetProcesses()
        {
            try { return Process.GetProcesses(); }
            catch { return Array.Empty<Process>(); }
        }
    }
}
