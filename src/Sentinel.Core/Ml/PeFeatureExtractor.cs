using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Sentinel.Core.Ml
{
    /// <summary>
    /// Extracts PE features compatible with the MalwareDataSet training columns.
    /// Best-effort parser: returns null if the file is not a readable PE.
    /// </summary>
    public static class PeFeatureExtractor
    {
        public static PeFeatureVector? TryExtract(string filePath)
        {
            try
            {
                if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
                    return null;

                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                if (fs.Length < 64) return null;
                return TryExtract(fs);
            }
            catch
            {
                return null;
            }
        }

        public static PeFeatureVector? TryExtract(Stream stream)
        {
            try
            {
                if (!stream.CanSeek || stream.Length < 64) return null;
                using var br = new BinaryReader(stream, Encoding.ASCII, leaveOpen: true);

                stream.Seek(0, SeekOrigin.Begin);
                if (br.ReadUInt16() != 0x5A4D) return null; // MZ

                stream.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                if (peOffset <= 0 || peOffset > stream.Length - 24) return null;

                stream.Seek(peOffset, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550) return null; // PE\0\0

                ushort machine = br.ReadUInt16();
                ushort numberOfSections = br.ReadUInt16();
                br.ReadUInt32(); // TimeDateStamp
                br.ReadUInt32(); // PointerToSymbolTable
                br.ReadUInt32(); // NumberOfSymbols
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                ushort characteristics = br.ReadUInt16();

                if (sizeOfOptionalHeader < 28) return null;
                long optStart = stream.Position;
                ushort magic = br.ReadUInt16();
                bool isPe32Plus = magic == 0x20B;
                if (magic != 0x10B && magic != 0x20B) return null;

                byte majorLinker = br.ReadByte();
                byte minorLinker = br.ReadByte();
                uint sizeOfCode = br.ReadUInt32();
                uint sizeOfInitData = br.ReadUInt32();
                uint sizeOfUninitData = br.ReadUInt32();
                uint addressOfEntryPoint = br.ReadUInt32();
                uint baseOfCode = br.ReadUInt32();
                uint baseOfData = 0;
                ulong imageBase;
                if (isPe32Plus)
                {
                    imageBase = br.ReadUInt64();
                }
                else
                {
                    baseOfData = br.ReadUInt32();
                    imageBase = br.ReadUInt32();
                }

                uint sectionAlignment = br.ReadUInt32();
                uint fileAlignment = br.ReadUInt32();
                ushort majorOs = br.ReadUInt16();
                ushort minorOs = br.ReadUInt16();
                ushort majorImage = br.ReadUInt16();
                ushort minorImage = br.ReadUInt16();
                ushort majorSubsystem = br.ReadUInt16();
                ushort minorSubsystem = br.ReadUInt16();
                br.ReadUInt32(); // Win32VersionValue
                uint sizeOfImage = br.ReadUInt32();
                uint sizeOfHeaders = br.ReadUInt32();
                uint checkSum = br.ReadUInt32();
                ushort subsystem = br.ReadUInt16();
                ushort dllCharacteristics = br.ReadUInt16();

                ulong stackReserve, stackCommit, heapReserve, heapCommit;
                if (isPe32Plus)
                {
                    stackReserve = br.ReadUInt64();
                    stackCommit = br.ReadUInt64();
                    heapReserve = br.ReadUInt64();
                    heapCommit = br.ReadUInt64();
                }
                else
                {
                    stackReserve = br.ReadUInt32();
                    stackCommit = br.ReadUInt32();
                    heapReserve = br.ReadUInt32();
                    heapCommit = br.ReadUInt32();
                }

                uint loaderFlags = br.ReadUInt32();
                uint numberOfRvaAndSizes = br.ReadUInt32();

                // Data directories (up to 16)
                var dataDirs = new (uint Va, uint Size)[16];
                int dirsToRead = (int)Math.Min(numberOfRvaAndSizes, 16u);
                for (int i = 0; i < dirsToRead; i++)
                {
                    dataDirs[i] = (br.ReadUInt32(), br.ReadUInt32());
                }

                // Section headers
                long sectionTable = optStart + sizeOfOptionalHeader;
                stream.Seek(sectionTable, SeekOrigin.Begin);

                var rawSizes = new List<float>(numberOfSections);
                var virtSizes = new List<float>(numberOfSections);
                var entropies = new List<float>(numberOfSections);
                var sections = new List<(uint Va, uint VSize, uint RawPtr, uint RawSize)>(numberOfSections);

                for (int i = 0; i < numberOfSections && i < 96; i++)
                {
                    br.ReadBytes(8); // name
                    uint vSize = br.ReadUInt32();
                    uint vAddr = br.ReadUInt32();
                    uint rawSize = br.ReadUInt32();
                    uint rawPtr = br.ReadUInt32();
                    br.ReadBytes(12); // relocs, linenumbers, counts
                    br.ReadUInt32(); // characteristics

                    rawSizes.Add(rawSize);
                    virtSizes.Add(vSize);
                    sections.Add((vAddr, vSize, rawPtr, rawSize));

                    float ent = 0;
                    if (rawSize > 0 && rawPtr > 0 && rawPtr + rawSize <= stream.Length)
                    {
                        long pos = stream.Position;
                        stream.Seek(rawPtr, SeekOrigin.Begin);
                        int sample = (int)Math.Min(rawSize, 65536u);
                        var buf = br.ReadBytes(sample);
                        ent = (float)Entropy(buf);
                        stream.Seek(pos, SeekOrigin.Begin);
                    }
                    entropies.Add(ent);
                }

                // Import / export counts (best-effort)
                var (importsDll, imports, importsOrd) = CountImports(stream, br, dataDirs, sections, isPe32Plus);
                int exportNb = CountExports(stream, br, dataDirs, sections);

                // Resource stats
                var (resNb, resMeanEnt, resMinEnt, resMaxEnt, resMeanSize, resMinSize, resMaxSize) =
                    AnalyzeResources(stream, br, dataDirs, sections);

                uint loadConfigSize = dataDirs.Length > 10 ? dataDirs[10].Size : 0;
                // Version info often lives in resources; approximate with resource total when present
                float versionInfoSize = resNb > 0 ? Math.Min(resMeanSize, 512) : 0;

                return new PeFeatureVector
                {
                    Machine = machine,
                    SizeOfOptionalHeader = sizeOfOptionalHeader,
                    Characteristics = characteristics,
                    MajorLinkerVersion = majorLinker,
                    MinorLinkerVersion = minorLinker,
                    SizeOfCode = sizeOfCode,
                    SizeOfInitializedData = sizeOfInitData,
                    SizeOfUninitializedData = sizeOfUninitData,
                    AddressOfEntryPoint = addressOfEntryPoint,
                    BaseOfCode = baseOfCode,
                    BaseOfData = baseOfData,
                    ImageBase = (float)Math.Min(imageBase, float.MaxValue),
                    SectionAlignment = sectionAlignment,
                    FileAlignment = fileAlignment,
                    MajorOperatingSystemVersion = majorOs,
                    MinorOperatingSystemVersion = minorOs,
                    MajorImageVersion = majorImage,
                    MinorImageVersion = minorImage,
                    MajorSubsystemVersion = majorSubsystem,
                    MinorSubsystemVersion = minorSubsystem,
                    SizeOfImage = sizeOfImage,
                    SizeOfHeaders = sizeOfHeaders,
                    CheckSum = checkSum,
                    Subsystem = subsystem,
                    DllCharacteristics = dllCharacteristics,
                    SizeOfStackReserve = (float)Math.Min(stackReserve, float.MaxValue),
                    SizeOfStackCommit = (float)Math.Min(stackCommit, float.MaxValue),
                    SizeOfHeapReserve = (float)Math.Min(heapReserve, float.MaxValue),
                    SizeOfHeapCommit = (float)Math.Min(heapCommit, float.MaxValue),
                    LoaderFlags = loaderFlags,
                    NumberOfRvaAndSizes = numberOfRvaAndSizes,
                    SectionsNb = numberOfSections,
                    SectionsMeanEntropy = Mean(entropies),
                    SectionsMinEntropy = MinOrZero(entropies),
                    SectionsMaxEntropy = MaxOrZero(entropies),
                    SectionsMeanRawsize = Mean(rawSizes),
                    SectionsMinRawsize = MinOrZero(rawSizes),
                    SectionMaxRawsize = MaxOrZero(rawSizes),
                    SectionsMeanVirtualsize = Mean(virtSizes),
                    SectionsMinVirtualsize = MinOrZero(virtSizes),
                    SectionMaxVirtualsize = MaxOrZero(virtSizes),
                    ImportsNbDLL = importsDll,
                    ImportsNb = imports,
                    ImportsNbOrdinal = importsOrd,
                    ExportNb = exportNb,
                    ResourcesNb = resNb,
                    ResourcesMeanEntropy = resMeanEnt,
                    ResourcesMinEntropy = resMinEnt,
                    ResourcesMaxEntropy = resMaxEnt,
                    ResourcesMeanSize = resMeanSize,
                    ResourcesMinSize = resMinSize,
                    ResourcesMaxSize = resMaxSize,
                    LoadConfigurationSize = loadConfigSize,
                    VersionInformationSize = versionInfoSize
                };
            }
            catch
            {
                return null;
            }
        }

        private static (int dlls, int imports, int ordinals) CountImports(
            Stream stream, BinaryReader br,
            (uint Va, uint Size)[] dataDirs,
            List<(uint Va, uint VSize, uint RawPtr, uint RawSize)> sections,
            bool isPe32Plus)
        {
            try
            {
                if (dataDirs.Length < 2 || dataDirs[1].Va == 0) return (0, 0, 0);
                long importTable = RvaToOffset(dataDirs[1].Va, sections);
                if (importTable < 0) return (0, 0, 0);

                int dlls = 0, imports = 0, ordinals = 0;
                for (int i = 0; i < 256; i++)
                {
                    stream.Seek(importTable + i * 20, SeekOrigin.Begin);
                    uint oft = br.ReadUInt32();
                    br.ReadUInt32(); // TimeDateStamp
                    br.ReadUInt32(); // ForwarderChain
                    uint nameRva = br.ReadUInt32();
                    uint ft = br.ReadUInt32();
                    if (oft == 0 && nameRva == 0 && ft == 0) break;
                    dlls++;

                    uint thunkRva = oft != 0 ? oft : ft;
                    long thunkOff = RvaToOffset(thunkRva, sections);
                    if (thunkOff < 0) continue;

                    int entrySize = isPe32Plus ? 8 : 4;
                    for (int t = 0; t < 4096; t++)
                    {
                        stream.Seek(thunkOff + t * entrySize, SeekOrigin.Begin);
                        ulong entry = isPe32Plus ? br.ReadUInt64() : br.ReadUInt32();
                        if (entry == 0) break;
                        imports++;
                        bool isOrd = isPe32Plus ? (entry & 0x8000000000000000UL) != 0 : (entry & 0x80000000U) != 0;
                        if (isOrd) ordinals++;
                    }
                }
                return (dlls, imports, ordinals);
            }
            catch { return (0, 0, 0); }
        }

        private static int CountExports(
            Stream stream, BinaryReader br,
            (uint Va, uint Size)[] dataDirs,
            List<(uint Va, uint VSize, uint RawPtr, uint RawSize)> sections)
        {
            try
            {
                if (dataDirs.Length < 1 || dataDirs[0].Va == 0) return 0;
                long off = RvaToOffset(dataDirs[0].Va, sections);
                if (off < 0) return 0;
                stream.Seek(off + 20, SeekOrigin.Begin); // NumberOfFunctions at +20? NumberOfNames at +24
                // IMAGE_EXPORT_DIRECTORY: Characteristics(0), TimeDateStamp(4), Major(8), Minor(10), Name(12), Base(16), NumberOfFunctions(20), NumberOfNames(24)
                stream.Seek(off + 24, SeekOrigin.Begin);
                return (int)br.ReadUInt32();
            }
            catch { return 0; }
        }

        private static (float nb, float meanEnt, float minEnt, float maxEnt, float meanSize, float minSize, float maxSize)
            AnalyzeResources(
                Stream stream, BinaryReader br,
                (uint Va, uint Size)[] dataDirs,
                List<(uint Va, uint VSize, uint RawPtr, uint RawSize)> sections)
        {
            try
            {
                if (dataDirs.Length < 3 || dataDirs[2].Va == 0 || dataDirs[2].Size == 0)
                    return (0, 0, 0, 0, 0, 0, 0);

                long resOff = RvaToOffset(dataDirs[2].Va, sections);
                if (resOff < 0) return (0, 0, 0, 0, 0, 0, 0);

                // Sample resource section raw bytes for entropy/size stats
                var sec = sections.Find(s => dataDirs[2].Va >= s.Va && dataDirs[2].Va < s.Va + Math.Max(s.VSize, 1u));
                if (sec.RawPtr == 0 || sec.RawSize == 0) return (0, 0, 0, 0, 0, 0, 0);

                stream.Seek(sec.RawPtr, SeekOrigin.Begin);
                int sampleLen = (int)Math.Min(sec.RawSize, 65536u);
                var buf = br.ReadBytes(sampleLen);
                float ent = (float)Entropy(buf);

                // Approximate resource count from directory entries (root level)
                stream.Seek(resOff, SeekOrigin.Begin);
                br.ReadUInt32(); // Characteristics
                br.ReadUInt32(); // TimeDateStamp
                br.ReadUInt16(); br.ReadUInt16(); // versions
                ushort named = br.ReadUInt16();
                ushort ids = br.ReadUInt16();
                int nb = named + ids;
                if (nb <= 0) nb = 1;

                float size = sec.RawSize;
                return (nb, ent, ent, ent, size / nb, Math.Min(size, 16), size);
            }
            catch
            {
                return (0, 0, 0, 0, 0, 0, 0);
            }
        }

        private static long RvaToOffset(uint rva, List<(uint Va, uint VSize, uint RawPtr, uint RawSize)> sections)
        {
            foreach (var s in sections)
            {
                uint span = Math.Max(s.VSize, s.RawSize);
                if (span == 0) span = s.RawSize;
                if (rva >= s.Va && rva < s.Va + Math.Max(span, 1u))
                    return s.RawPtr + (rva - s.Va);
            }
            return -1;
        }

        private static double Entropy(byte[] data)
        {
            if (data.Length == 0) return 0;
            var freq = new int[256];
            foreach (var b in data) freq[b]++;
            double ent = 0, len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = freq[i] / len;
                ent -= p * MathNet48.Log2(p);
            }
            return ent;
        }

        private static float Mean(List<float> v)
        {
            if (v.Count == 0) return 0;
            double s = 0;
            foreach (var x in v) s += x;
            return (float)(s / v.Count);
        }

        private static float MinOrZero(List<float> v)
        {
            if (v.Count == 0) return 0;
            float m = v[0];
            for (int i = 1; i < v.Count; i++) if (v[i] < m) m = v[i];
            return m;
        }

        private static float MaxOrZero(List<float> v)
        {
            if (v.Count == 0) return 0;
            float m = v[0];
            for (int i = 1; i < v.Count; i++) if (v[i] > m) m = v[i];
            return m;
        }
    }
}
