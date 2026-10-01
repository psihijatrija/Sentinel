using Microsoft.ML.Data;

namespace Sentinel.Core.Ml
{
    /// <summary>
    /// PE static features aligned with the public MalwareDataSet CSV used for training
    /// (Kaggle-style PE header/section stats). Feature names must match the trainer pipeline.
    /// </summary>
    public sealed class PeFeatureVector
    {
        public float Machine { get; set; }
        public float SizeOfOptionalHeader { get; set; }
        public float Characteristics { get; set; }
        public float MajorLinkerVersion { get; set; }
        public float MinorLinkerVersion { get; set; }
        public float SizeOfCode { get; set; }
        public float SizeOfInitializedData { get; set; }
        public float SizeOfUninitializedData { get; set; }
        public float AddressOfEntryPoint { get; set; }
        public float BaseOfCode { get; set; }
        public float BaseOfData { get; set; }
        public float ImageBase { get; set; }
        public float SectionAlignment { get; set; }
        public float FileAlignment { get; set; }
        public float MajorOperatingSystemVersion { get; set; }
        public float MinorOperatingSystemVersion { get; set; }
        public float MajorImageVersion { get; set; }
        public float MinorImageVersion { get; set; }
        public float MajorSubsystemVersion { get; set; }
        public float MinorSubsystemVersion { get; set; }
        public float SizeOfImage { get; set; }
        public float SizeOfHeaders { get; set; }
        public float CheckSum { get; set; }
        public float Subsystem { get; set; }
        public float DllCharacteristics { get; set; }
        public float SizeOfStackReserve { get; set; }
        public float SizeOfStackCommit { get; set; }
        public float SizeOfHeapReserve { get; set; }
        public float SizeOfHeapCommit { get; set; }
        public float LoaderFlags { get; set; }
        public float NumberOfRvaAndSizes { get; set; }
        public float SectionsNb { get; set; }
        public float SectionsMeanEntropy { get; set; }
        public float SectionsMinEntropy { get; set; }
        public float SectionsMaxEntropy { get; set; }
        public float SectionsMeanRawsize { get; set; }
        public float SectionsMinRawsize { get; set; }
        public float SectionMaxRawsize { get; set; }
        public float SectionsMeanVirtualsize { get; set; }
        public float SectionsMinVirtualsize { get; set; }
        public float SectionMaxVirtualsize { get; set; }
        public float ImportsNbDLL { get; set; }
        public float ImportsNb { get; set; }
        public float ImportsNbOrdinal { get; set; }
        public float ExportNb { get; set; }
        public float ResourcesNb { get; set; }
        public float ResourcesMeanEntropy { get; set; }
        public float ResourcesMinEntropy { get; set; }
        public float ResourcesMaxEntropy { get; set; }
        public float ResourcesMeanSize { get; set; }
        public float ResourcesMinSize { get; set; }
        public float ResourcesMaxSize { get; set; }
        public float LoadConfigurationSize { get; set; }
        public float VersionInformationSize { get; set; }

        /// <summary>True when this row is malware (inverse of dataset "legitimate" column).</summary>
        public bool Label { get; set; }

        public static readonly string[] FeatureNames =
        {
            nameof(Machine), nameof(SizeOfOptionalHeader), nameof(Characteristics),
            nameof(MajorLinkerVersion), nameof(MinorLinkerVersion), nameof(SizeOfCode),
            nameof(SizeOfInitializedData), nameof(SizeOfUninitializedData), nameof(AddressOfEntryPoint),
            nameof(BaseOfCode), nameof(BaseOfData), nameof(ImageBase), nameof(SectionAlignment),
            nameof(FileAlignment), nameof(MajorOperatingSystemVersion), nameof(MinorOperatingSystemVersion),
            nameof(MajorImageVersion), nameof(MinorImageVersion), nameof(MajorSubsystemVersion),
            nameof(MinorSubsystemVersion), nameof(SizeOfImage), nameof(SizeOfHeaders), nameof(CheckSum),
            nameof(Subsystem), nameof(DllCharacteristics), nameof(SizeOfStackReserve),
            nameof(SizeOfStackCommit), nameof(SizeOfHeapReserve), nameof(SizeOfHeapCommit),
            nameof(LoaderFlags), nameof(NumberOfRvaAndSizes), nameof(SectionsNb),
            nameof(SectionsMeanEntropy), nameof(SectionsMinEntropy), nameof(SectionsMaxEntropy),
            nameof(SectionsMeanRawsize), nameof(SectionsMinRawsize), nameof(SectionMaxRawsize),
            nameof(SectionsMeanVirtualsize), nameof(SectionsMinVirtualsize), nameof(SectionMaxVirtualsize),
            nameof(ImportsNbDLL), nameof(ImportsNb), nameof(ImportsNbOrdinal), nameof(ExportNb),
            nameof(ResourcesNb), nameof(ResourcesMeanEntropy), nameof(ResourcesMinEntropy),
            nameof(ResourcesMaxEntropy), nameof(ResourcesMeanSize), nameof(ResourcesMinSize),
            nameof(ResourcesMaxSize), nameof(LoadConfigurationSize), nameof(VersionInformationSize)
        };
    }

    /// <summary>Lexical URL features for the URLDataSet-trained model.</summary>
    public sealed class UrlFeatureVector
    {
        public float UrlLength { get; set; }
        public float HostLength { get; set; }
        public float PathLength { get; set; }
        public float QueryLength { get; set; }
        public float DigitCount { get; set; }
        public float LetterCount { get; set; }
        public float SpecialCharCount { get; set; }
        public float DotCount { get; set; }
        public float HyphenCount { get; set; }
        public float UnderscoreCount { get; set; }
        public float SlashCount { get; set; }
        public float QuestionCount { get; set; }
        public float EqualsCount { get; set; }
        public float AtCount { get; set; }
        public float AmpCount { get; set; }
        public float PercentCount { get; set; }
        public float DigitRatio { get; set; }
        public float Entropy { get; set; }
        public float HasIpHost { get; set; }
        public float HasHttps { get; set; }
        public float HasHttp { get; set; }
        public float SubdomainCount { get; set; }
        public float TldLength { get; set; }
        public float HasSuspiciousTld { get; set; }
        public float HasShortenerHint { get; set; }
        public float DoubleSlashCount { get; set; }

        /// <summary>True when URL is labeled bad/malicious.</summary>
        public bool Label { get; set; }

        public static readonly string[] FeatureNames =
        {
            nameof(UrlLength), nameof(HostLength), nameof(PathLength), nameof(QueryLength),
            nameof(DigitCount), nameof(LetterCount), nameof(SpecialCharCount), nameof(DotCount),
            nameof(HyphenCount), nameof(UnderscoreCount), nameof(SlashCount), nameof(QuestionCount),
            nameof(EqualsCount), nameof(AtCount), nameof(AmpCount), nameof(PercentCount),
            nameof(DigitRatio), nameof(Entropy), nameof(HasIpHost), nameof(HasHttps), nameof(HasHttp),
            nameof(SubdomainCount), nameof(TldLength), nameof(HasSuspiciousTld),
            nameof(HasShortenerHint), nameof(DoubleSlashCount)
        };
    }

    /// <summary>
    /// Lexical / statistical features for the command-line obfuscation model.
    ///
    /// Modern tradecraft (CrowdStrike 2026 GTR, arXiv 2408.02637) increasingly lives off signed,
    /// trusted binaries (LOLBins) with obfuscated command lines that defeat signature / regex
    /// matching. These features capture the *shape* of obfuscation - encoding density, escape-char
    /// stuffing, environment-variable substitution, base64/hex payloads - independent of the exact
    /// tokens, so the model generalises across obfuscation variants rather than one-off signatures.
    ///
    /// This is a SOFT signal only: it feeds correlation / observe-fuel, never sole kill authority.
    /// </summary>
    public sealed class CommandLineFeatureVector
    {
        public float Length { get; set; }
        public float TokenCount { get; set; }
        public float DigitRatio { get; set; }
        public float UpperRatio { get; set; }
        public float SpecialRatio { get; set; }
        public float Entropy { get; set; }
        /// <summary>Longest run of chars that look like a base64/hex alphabet blob.</summary>
        public float MaxAlnumRunLength { get; set; }
        public float Base64CharRatio { get; set; }
        public float HexCharRatio { get; set; }
        public float CaretCount { get; set; }         // cmd.exe ^ escape stuffing
        public float BacktickCount { get; set; }       // powershell ` escape stuffing
        public float EnvVarRefCount { get; set; }      // %VAR% / $env: substitution
        public float QuoteCount { get; set; }
        public float ParenBraceCount { get; set; }     // ( ) { } - PS expression obfuscation
        public float PlusCount { get; set; }           // string concat obfuscation
        public float CommaCount { get; set; }
        public float HasEncodedCommandFlag { get; set; } // -enc / -e / -encodedcommand
        public float HasHiddenWindowFlag { get; set; }   // -w hidden / -windowstyle hidden
        public float HasExecBypassFlag { get; set; }     // -ep bypass / -executionpolicy bypass
        public float HasDownloadToken { get; set; }      // downloadstring / iwr / curl / bitsadmin ...
        public float HasIexToken { get; set; }           // iex / invoke-expression
        public float HasLolbinToken { get; set; }        // rundll32 / regsvr32 / mshta / certutil ...
        public float NonAsciiRatio { get; set; }

        /// <summary>True when this command line is labeled malicious/obfuscated.</summary>
        public bool Label { get; set; }

        public static readonly string[] FeatureNames =
        {
            nameof(Length), nameof(TokenCount), nameof(DigitRatio), nameof(UpperRatio),
            nameof(SpecialRatio), nameof(Entropy), nameof(MaxAlnumRunLength), nameof(Base64CharRatio),
            nameof(HexCharRatio), nameof(CaretCount), nameof(BacktickCount), nameof(EnvVarRefCount),
            nameof(QuoteCount), nameof(ParenBraceCount), nameof(PlusCount), nameof(CommaCount),
            nameof(HasEncodedCommandFlag), nameof(HasHiddenWindowFlag), nameof(HasExecBypassFlag),
            nameof(HasDownloadToken), nameof(HasIexToken), nameof(HasLolbinToken), nameof(NonAsciiRatio)
        };
    }

    public sealed class MlBinaryPrediction
    {
        [ColumnName("PredictedLabel")]
        public bool PredictedLabel { get; set; }

        [ColumnName("Probability")]
        public float Probability { get; set; }

        [ColumnName("Score")]
        public float Score { get; set; }
    }
}
