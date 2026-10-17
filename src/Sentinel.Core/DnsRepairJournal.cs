using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace Sentinel.Core
{
    public sealed class DnsRepairJournal : IDnsRepairJournal
    {
        private readonly string _directory;
        public DnsRepairJournal() : this(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Sentinel", "DnsRepair")) { }
        internal DnsRepairJournal(string directory) => _directory = Path.GetFullPath(directory);
        private void EnsureStorage()
        {
            // Optional repair storage must not prevent the monitoring service from starting.
            // Inspection/mutation still fails closed if storage cannot be secured.
            Directory.CreateDirectory(_directory);
            var directory = new DirectoryInfo(_directory);
            if ((directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (directory.Parent!.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("DNS repair storage cannot be a reparse point.");
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.SetOwner(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.ReadAndExecute, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            directory.SetAccessControl(acl);
        }
        public IReadOnlyList<DnsRepairRecord> ReadAll()
        {
            EnsureStorage();
            var records = new List<DnsRepairRecord>();
            foreach (string file in Directory.EnumerateFiles(_directory, "*.json"))
            {
                if (records.Count >= 128) throw new IOException("DNS repair journal capacity reached; archive records before further changes.");
                var info = new FileInfo(file);
                if (info.Length > 65536 || (info.Attributes & FileAttributes.ReparsePoint) != 0)
                    throw new IOException("Invalid DNS repair journal file.");
                var record = JsonSerializer.Deserialize<DnsRepairRecord>(File.ReadAllText(file));
                if (record == null || !Guid.TryParseExact(record.Id, "N", out _) || Path.GetFileNameWithoutExtension(file) != record.Id)
                    throw new IOException("Invalid DNS repair journal identity.");
                records.Add(record);
            }
            return records;
        }
        public void Save(DnsRepairRecord record)
        {
            EnsureStorage();
            if (!Guid.TryParseExact(record.Id, "N", out _)) throw new ArgumentException("Invalid transaction identity.");
            if (!File.Exists(Path.Combine(_directory, record.Id + ".json")) && ReadAll().Count >= 128)
                throw new IOException("DNS repair journal capacity reached.");
            string path = Path.Combine(_directory, record.Id + ".json");
            string temporary = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                byte[] bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(record));
                if (bytes.Length > 65536) throw new IOException("DNS repair snapshot is too large.");
                using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { file.Write(bytes, 0, bytes.Length); file.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null);
                else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
