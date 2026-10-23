using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace Sentinel.Core
{
    // Read-only, bounded inspection of a single already-authorized process handle.
    // Delegates let tests exercise this exact walk without opening another process.
    internal static class UnbackedPeScanner
    {
        internal readonly struct Payload
        {
            internal Payload(ulong allocation, ulong executablePage, uint protection)
            { Allocation = allocation; ExecutablePage = executablePage; Protection = protection; }
            internal ulong Allocation { get; }
            internal ulong ExecutablePage { get; }
            internal uint Protection { get; }
        }

        internal static bool IsCandidate(NativeProcessMemory.MEMORY_BASIC_INFORMATION region) =>
            region.State == NativeProcessMemory.MEM_COMMIT && region.Type == NativeProcessMemory.TypePrivate && // MEM_PRIVATE only
            (region.Protect & 0x100) == 0 && // never touch PAGE_GUARD
            NativeProcessMemory.IsExecutableProtection(region.Protect & 0xff) &&
            region.RegionSize.ToInt64() > 0 && region.AllocationBase != IntPtr.Zero;

        internal static IReadOnlyList<Payload> Scan(
            Func<ulong, NativeProcessMemory.MEMORY_BASIC_INFORMATION?> query,
            Func<ulong, byte[]?> readHeader,
            CancellationToken ct, ulong startAddress = 0)
        {
            var results = new List<Payload>();
            var inspected = new HashSet<ulong>();
            var budget = Stopwatch.StartNew();
            ulong address = startAddress;
            for (int pages = 0; pages < 10000 && inspected.Count < 128 &&
                results.Count < 8 && budget.ElapsedMilliseconds < 250; pages++)
            {
                ct.ThrowIfCancellationRequested();
                var value = query(address);
                if (!value.HasValue) break;
                var region = value.Value;
                ulong start = unchecked((ulong)region.BaseAddress.ToInt64());
                long size = region.RegionSize.ToInt64();
                if (start > address || size <= 0 || (ulong)size > ulong.MaxValue - start) break;
                ulong next = start + (ulong)size;
                if (next <= address) break;

                if (IsCandidate(region))
                {
                    ulong allocation = unchecked((ulong)region.AllocationBase.ToInt64());
                    if (allocation <= start && inspected.Add(allocation))
                    {
                        // The PE header is commonly READONLY while its code section is RX.
                        var head = query(allocation);
                        if (head.HasValue && head.Value.AllocationBase == region.AllocationBase &&
                            head.Value.BaseAddress == region.AllocationBase &&
                            head.Value.State == NativeProcessMemory.MEM_COMMIT && head.Value.Type == NativeProcessMemory.TypePrivate &&
                            (head.Value.Protect & 0x100) == 0 &&
                            (head.Value.Protect & 0xff) != 0x01 && head.Value.Protect != 0)
                        {
                            ct.ThrowIfCancellationRequested();
                            var bytes = readHeader(allocation);
                            if (bytes != null && HasExecutableSection(bytes, start - allocation, (ulong)size))
                            {
                                results.Add(new Payload(allocation, start, region.Protect));
                            }
                        }
                    }
                }
                address = next;
            }
            return results;
        }

        private static bool HasExecutableSection(byte[] header, ulong pageRva, ulong pageSize)
        {
            if (!NativeProcessMemory.HasPeHeaders(header, header.Length)) return false;
            int pe = BitConverter.ToInt32(header, 0x3c);
            uint imageSize = BitConverter.ToUInt32(header, pe + 24 + 56);
            if (pageRva >= imageSize) return false;
            int count = BitConverter.ToUInt16(header, pe + 6);
            int table = pe + 24 + BitConverter.ToUInt16(header, pe + 20);
            if (table > header.Length || count > (header.Length - table) / 40) return false;
            ulong pageEnd = pageRva + Math.Min(pageSize, imageSize);
            for (int index = 0; index < count; index++)
            {
                int section = table + index * 40;
                uint flags = BitConverter.ToUInt32(header, section + 36);
                if ((flags & 0x20000000) == 0) continue; // IMAGE_SCN_MEM_EXECUTE
                uint start = BitConverter.ToUInt32(header, section + 12);
                uint size = Math.Max(BitConverter.ToUInt32(header, section + 8),
                    BitConverter.ToUInt32(header, section + 16));
                ulong end = (ulong)start + size;
                if (size > 0 && end <= imageSize && pageRva < end && pageEnd > start) return true;
            }
            return false;
        }
    }
}
