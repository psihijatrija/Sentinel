using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Sentinel.Core
{
    /// <summary>
    /// Country-aware cybercrime reporting portal directory.
    /// INTERPOL and Europol do not accept direct public reports - citizens must file
    /// with national / local channels; those agencies escalate internationally when needed.
    /// </summary>
    public static class LawEnforcementPortals
    {
        public sealed record PortalEntry(
            string CountryCode,
            string CountryName,
            string PrimaryPortalName,
            string PrimaryPortalUrl,
            string Notes);

        /// <summary>
        /// Curated national cybercrime reporting entry points (human web portals).
        /// Kept intentionally short; unknown countries fall back to Europol's directory.
        /// </summary>
        private static readonly IReadOnlyDictionary<string, PortalEntry> Portals =
            new Dictionary<string, PortalEntry>(StringComparer.OrdinalIgnoreCase)
            {
                ["US"] = new("US", "United States",
                    "FBI Internet Crime Complaint Center (IC3)",
                    "https://www.ic3.gov/",
                    "Primary US federal cybercrime intake. Save/print the complaint after filing - IC3 does not email a copy."),
                ["GB"] = new("GB", "United Kingdom",
                    "Action Fraud / Report cybercrime",
                    "https://www.actionfraud.police.uk/",
                    "UK national fraud and cybercrime reporting. Also contact local police for ongoing attacks."),
                ["UK"] = new("UK", "United Kingdom",
                    "Action Fraud / Report cybercrime",
                    "https://www.actionfraud.police.uk/",
                    "UK national fraud and cybercrime reporting. Also contact local police for ongoing attacks."),
                ["CA"] = new("CA", "Canada",
                    "Canadian Centre for Cyber Security - Report a cyber incident",
                    "https://www.cyber.gc.ca/en/incident-management",
                    "Use the national flow to locate the correct federal/provincial reporting path."),
                ["AU"] = new("AU", "Australia",
                    "ReportCyber (ACSC)",
                    "https://www.cyber.gov.au/report-and-recover/report",
                    "Australian Cyber Security Centre national cybercrime reporting."),
                ["NZ"] = new("NZ", "New Zealand",
                    "ReportCyber NZ",
                    "https://www.ncsc.govt.nz/report/",
                    "New Zealand cyber security incident reporting."),
                ["DE"] = new("DE", "Germany",
                    "Bundeskriminalamt / Polizei online reporting",
                    "https://www.polizei.de/Polizei/DE/Einrichtungen/ZAC/zac_node.html",
                    "File with local police (Polizei) or state cybercrime units; BKA coordinates serious cases."),
                ["FR"] = new("FR", "France",
                    "Service public - plainte en ligne / cybermalveillance",
                    "https://www.cybermalveillance.gouv.fr/",
                    "French national cyber assistance and reporting guidance."),
                ["NL"] = new("NL", "Netherlands",
                    "Politie - cybercrime melden",
                    "https://www.politie.nl/aangifte-of-melding-doen",
                    "Report via Dutch police; serious cybercrime is handled by specialized units."),
                ["BE"] = new("BE", "Belgium",
                    "Police / eCops",
                    "https://www.police.be/",
                    "Belgian police online reporting channels."),
                ["ES"] = new("ES", "Spain",
                    "Polica Nacional / Guardia Civil denuncias",
                    "https://www.policia.es/_es/denuncias.php",
                    "Spain: national police or Guardia Civil electronic complaints."),
                ["IT"] = new("IT", "Italy",
                    "Polizia Postale",
                    "https://www.commissariatodips.it/",
                    "Italian postal and communications police cybercrime portal."),
                ["HR"] = new("HR", "Croatia",
                    "MUP / police reporting",
                    "https://mup.gov.hr/",
                    "Report to Croatian police (MUP). Preserve Sentinel evidence packs for the complaint."),
                ["AT"] = new("AT", "Austria",
                    "Polizei.gv.at",
                    "https://www.polizei.gv.at/",
                    "Austrian police reporting."),
                ["CH"] = new("CH", "Switzerland",
                    "Swiss cybercrime reporting (MELANI / police)",
                    "https://www.ncsc.admin.ch/",
                    "Swiss NCSC guidance; file criminal complaints with cantonal police."),
                ["SE"] = new("SE", "Sweden",
                    "Polisen - anmlan",
                    "https://polisen.se/",
                    "Swedish police online reporting."),
                ["NO"] = new("NO", "Norway",
                    "Politiet - anmelde",
                    "https://www.politiet.no/",
                    "Norwegian police reporting."),
                ["DK"] = new("DK", "Denmark",
                    "Politi - anmeld",
                    "https://politi.dk/",
                    "Danish police reporting."),
                ["FI"] = new("FI", "Finland",
                    "Poliisi",
                    "https://www.poliisi.fi/",
                    "Finnish police reporting."),
                ["PL"] = new("PL", "Poland",
                    "Policja / CERT Polska",
                    "https://www.cert.pl/",
                    "CERT Polska for incidents; criminal complaints via Polish police."),
                ["CZ"] = new("CZ", "Czechia",
                    "Policie ČR",
                    "https://www.policie.cz/",
                    "Czech police reporting."),
                ["IE"] = new("IE", "Ireland",
                    "Garda - report a crime",
                    "https://www.garda.ie/",
                    "An Garda Sochna reporting."),
                ["PT"] = new("PT", "Portugal",
                    "Polcia Judiciria / online reporting",
                    "https://www.policiajudiciaria.pt/",
                    "Portuguese criminal investigation police for serious cybercrime."),
                ["IN"] = new("IN", "India",
                    "National Cyber Crime Reporting Portal",
                    "https://cybercrime.gov.in/",
                    "Indian national cybercrime portal; financial fraud helpline 1930."),
                ["JP"] = new("JP", "Japan",
                    "National Police Agency / cybercrime consultation",
                    "https://www.npa.go.jp/",
                    "Report via Japanese police / NPA cybercrime channels."),
                ["KR"] = new("KR", "South Korea",
                    "Korean National Police cyber bureau",
                    "https://www.police.go.kr/",
                    "Korean police cybercrime reporting."),
                ["SG"] = new("SG", "Singapore",
                    "ScamShield / SPF report",
                    "https://www.scamshield.gov.sg/",
                    "Singapore scam and cybercrime reporting."),
                ["BR"] = new("BR", "Brazil",
                    "Polcia Civil / SaferNet",
                    "https://www.gov.br/",
                    "Report to state civil police cyber units; SaferNet for certain online crimes."),
                ["MX"] = new("MX", "Mexico",
                    "Guardia Nacional / cybercrime units",
                    "https://www.gob.mx/",
                    "Mexican federal/state cybercrime reporting channels."),
                ["ZA"] = new("ZA", "South Africa",
                    "SAPS / cybercrime",
                    "https://www.saps.gov.za/",
                    "South African Police Service reporting."),
            };

        public static readonly PortalEntry EuropolDirectory = new(
            "EU", "European Union (directory)",
            "Europol - Report cybercrime online (per-country links)",
            "https://www.europol.europa.eu/report-a-crime/report-cybercrime-online",
            "Europol does not accept direct public complaints. This page redirects to your national portal.");

        public static readonly PortalEntry InterpolInfo = new(
            "INT", "International (INTERPOL)",
            "INTERPOL Cybercrime - individuals cannot report directly",
            "https://www.interpol.int/en/Crimes/Cybercrime/Cybercrime-our-response",
            "INTERPOL FAQ: individuals cannot report cybercrime directly. File with local LE; they escalate via INTERPOL if needed.");

        /// <summary>
        /// Resolves the best portal for the given ISO country code, or system region when null/empty.
        /// </summary>
        public static PortalEntry Resolve(string? countryCode = null)
        {
            var code = NormalizeCountryCode(countryCode) ?? DetectSystemCountryCode();
            if (!string.IsNullOrEmpty(code) && Portals.TryGetValue(code, out var entry))
                return entry;

            // EU-ish fallback when region is European but not in table
            if (!string.IsNullOrEmpty(code) && IsLikelyEuropean(code))
                return EuropolDirectory;

            // Ultimate fallback: Europol directory + INTERPOL note in pack text
            return EuropolDirectory;
        }

        public static string DetectSystemCountryCode()
        {
            try
            {
                var region = new RegionInfo(CultureInfo.CurrentCulture.Name);
                return region.TwoLetterISORegionName;
            }
            catch
            {
                try
                {
                    return RegionInfo.CurrentRegion.TwoLetterISORegionName;
                }
                catch
                {
                    return "US";
                }
            }
        }

        public static IReadOnlyList<PortalEntry> GetAllNationalPortals() =>
            Portals.Values
                .GroupBy(p => p.CountryCode, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .OrderBy(p => p.CountryName, StringComparer.OrdinalIgnoreCase)
                .ToList();

        private static string? NormalizeCountryCode(string? code)
        {
            if (string.IsNullOrWhiteSpace(code)) return null;
            code = code!.Trim().ToUpperInvariant();
            if (code.Equals("UK")) return "GB";
            return code.Length == 2 ? code : null;
        }

        private static bool IsLikelyEuropean(string code) =>
            code is "AL" or "AD" or "AM" or "BA" or "BG" or "BY" or "CY" or "EE" or "GE"
                or "GR" or "HU" or "IS" or "LI" or "LT" or "LU" or "LV" or "MC" or "MD"
                or "ME" or "MK" or "MT" or "RO" or "RS" or "SI" or "SK" or "SM" or "UA" or "VA";
    }
}
