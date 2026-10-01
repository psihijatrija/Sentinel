namespace Sentinel.Agent
{
    /// <summary>
    /// Self-contained HTML/CSS/JS for the Sentinel web dashboard.
    /// Embedded as a static string to avoid external file dependencies.
    /// 
    /// v2.2.9: Rewritten with IE11-compatible JavaScript (no ES6+) and
    /// GBrowser-inspired dark/creamy/mica theme for visual consistency.
    /// </summary>
    public static class DashboardHtml
    {
        public static string GetHtml(string? embeddedToken = null) => $@"<!DOCTYPE html>
<html lang=""en"">
<head>
<meta charset=""UTF-8"">
<meta http-equiv=""X-UA-Compatible"" content=""IE=edge"">
<meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
<title>Sentinel Dashboard</title>
<script>var EMBEDDED_TOKEN = '{embeddedToken ?? ""}';</script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #202124;
    color: #e8eaed;
    line-height: 1.5;
    overflow: hidden;
    height: 100vh;
}}
.layout {{ display: flex; height: 100vh; }}
.sidebar {{
    width: 220px;
    background: rgba(32,33,36,0.92);
    border-right: 1px solid #3c4043;
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
}}
.sidebar-header {{
    padding: 20px 16px;
    border-bottom: 1px solid #3c4043;
    display: flex;
    align-items: center;
    gap: 10px;
}}
.sidebar-header .logo {{
    width: 32px; height: 32px;
    background: linear-gradient(135deg, #8ab4f8, #c58af9);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-weight: bold; font-size: 16px; color: #202124;
}}
.sidebar-header h1 {{ font-size: 15px; font-weight: 600; color: #e8eaed; }}
.sidebar-header .version {{ font-size: 11px; color: #9aa0a6; }}
.nav {{ flex: 1; padding: 8px; overflow-y: auto; }}
.nav-item {{
    display: flex; align-items: center; gap: 10px;
    padding: 9px 12px; border-radius: 4px;
    cursor: pointer; color: #b4b8be;
    font-size: 13px; margin-bottom: 1px;
    border: 1px solid transparent;
    transition: background 0.12s, color 0.12s;
}}
.nav-item:hover {{ background: #303135; color: #e8eaed; }}
.nav-item.active {{
    background: rgba(138,180,248,0.12);
    color: #8ab4f8;
    border-color: rgba(138,180,248,0.25);
}}
.nav-item svg {{ width: 16px; height: 16px; flex-shrink: 0; }}
.main {{ flex: 1; display: flex; flex-direction: column; overflow: hidden; background: #202124; }}
.header {{
    height: 56px;
    padding: 0 24px;
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 1px solid #3c4043;
    background: rgba(53,54,58,0.7);
    backdrop-filter: blur(12px);
    -webkit-backdrop-filter: blur(12px);
}}
.header h2 {{ font-size: 16px; font-weight: 600; color: #e8eaed; }}
.status-badge {{
    display: flex; align-items: center; gap: 6px;
    padding: 5px 12px; border-radius: 16px; font-size: 12px; font-weight: 500;
}}
.status-badge.active {{ background: rgba(129,201,149,0.12); color: #81c995; }}
.status-badge.inactive {{ background: rgba(242,139,130,0.12); color: #f28b82; }}
.status-dot {{ width: 7px; height: 7px; border-radius: 50%; animation: pulse 2s infinite; }}
.status-badge.active .status-dot {{ background: #81c995; }}
.status-badge.inactive .status-dot {{ background: #f28b82; }}
@keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.5; }} }}
.content {{ flex: 1; overflow-y: auto; padding: 20px 24px; }}
.page {{ display: none; }}
.page.active {{ display: block; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.card {{
    background: #292a2d;
    border: 1px solid #3c4043;
    border-radius: 8px; padding: 16px;
    transition: border-color 0.15s;
}}
.card:hover {{ border-color: #8ab4f8; }}
.card-label {{ font-size: 11px; color: #9aa0a6; text-transform: uppercase; letter-spacing: 0.4px; margin-bottom: 4px; }}
.card-value {{ font-size: 26px; font-weight: 700; color: #e8eaed; }}
.card-value.success {{ color: #81c995; }}
.card-value.warning {{ color: #fdd663; }}
.card-value.danger {{ color: #f28b82; }}
.card-sub {{ font-size: 11px; color: #9aa0a6; margin-top: 3px; }}
.panel {{
    background: #292a2d;
    border: 1px solid #3c4043;
    border-radius: 8px; margin-bottom: 20px;
}}
.panel-header {{
    padding: 14px 16px; border-bottom: 1px solid #3c4043;
    display: flex; align-items: center; justify-content: space-between;
}}
.panel-header h3 {{ font-size: 13px; font-weight: 600; color: #e8eaed; }}
.panel-body {{ padding: 14px 16px; }}
.event-list {{ max-height: 380px; overflow-y: auto; }}
.event-item {{
    display: flex; align-items: flex-start; gap: 10px; padding: 10px 0;
    border-bottom: 1px solid #3c4043; font-size: 12px;
}}
.event-item:last-child {{ border-bottom: none; }}
.event-icon {{
    width: 28px; height: 28px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0; font-size: 12px;
}}
.event-icon.detection {{ background: rgba(242,139,130,0.12); color: #f28b82; }}
.event-icon.response {{ background: rgba(129,201,149,0.12); color: #81c995; }}
.event-icon.info {{ background: rgba(138,180,248,0.12); color: #8ab4f8; }}
.event-body {{ flex: 1; min-width: 0; }}
.event-title {{ font-weight: 500; color: #e8eaed; font-size: 12px; }}
.event-detail {{ color: #9aa0a6; margin-top: 2px; word-break: break-word; font-size: 11px; }}
.event-time {{ color: #9aa0a6; font-size: 10px; white-space: nowrap; }}
.btn {{
    padding: 7px 14px; border-radius: 4px; border: 1px solid #3c4043;
    background: #35363a; color: #e8eaed; cursor: pointer;
    font-size: 12px; font-weight: 500; transition: background 0.12s;
    display: inline-flex; align-items: center; gap: 6px;
    font-family: 'Segoe UI', sans-serif;
}}
.btn:hover {{ background: #3c4043; border-color: #8ab4f8; }}
.btn-primary {{ background: #8ab4f8; border-color: #8ab4f8; color: #202124; font-weight: 600; }}
.btn-primary:hover {{ background: #aecbfa; }}
.btn-danger {{ background: #f28b82; border-color: #f28b82; color: #202124; font-weight: 600; }}
.btn-danger:hover {{ background: #f6aea8; }}
.scan-progress {{ margin: 16px 0; }}
.progress-bar {{
    height: 5px; background: #35363a; border-radius: 3px; overflow: hidden;
}}
.progress-fill {{
    height: 100%; background: linear-gradient(90deg, #8ab4f8, #c58af9);
    border-radius: 3px; transition: width 0.3s; animation: shimmer 1.5s infinite;
}}
@keyframes shimmer {{ 0% {{ opacity: 0.7; }} 50% {{ opacity: 1; }} 100% {{ opacity: 0.7; }} }}
.findings-grid {{ display: grid; gap: 6px; }}
.finding {{
    display: flex; align-items: flex-start; gap: 10px; padding: 10px 12px;
    border-radius: 4px; border: 1px solid #3c4043; background: #35363a;
}}
.finding-severity {{
    width: 7px; height: 7px; border-radius: 50%; margin-top: 5px; flex-shrink: 0;
}}
.finding-severity.critical {{ background: #f28b82; }}
.finding-severity.high {{ background: #f28b82; }}
.finding-severity.medium {{ background: #fdd663; }}
.finding-severity.low {{ background: #9aa0a6; }}
.finding-body {{ flex: 1; }}
.finding-title {{ font-weight: 500; font-size: 12px; color: #e8eaed; }}
.finding-desc {{ font-size: 11px; color: #9aa0a6; margin-top: 2px; }}
.chart-container {{ height: 160px; position: relative; margin: 12px 0; }}
.bar-chart {{ display: flex; align-items: flex-end; gap: 3px; height: 100%; padding: 0 4px; }}
.bar {{
    flex: 1; min-width: 2px; background: #8ab4f8; border-radius: 2px 2px 0 0;
    transition: height 0.3s ease; opacity: 0.7;
}}
.bar:hover {{ opacity: 1; }}
.metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; }}
.metric {{
    padding: 10px; border-radius: 4px; background: #35363a;
    border: 1px solid #3c4043;
}}
.metric-label {{ font-size: 10px; color: #9aa0a6; text-transform: uppercase; letter-spacing: 0.3px; }}
.metric-value {{ font-size: 18px; font-weight: 600; margin-top: 2px; color: #e8eaed; }}
.empty-state {{
    text-align: center; padding: 40px 20px; color: #9aa0a6; font-size: 13px;
}}
.quarantine-item {{
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 0; border-bottom: 1px solid #3c4043; font-size: 12px;
}}
.quarantine-item:last-child {{ border-bottom: none; }}
.q-path {{ color: #9aa0a6; font-family: 'Consolas', monospace; font-size: 11px; }}
.rp-input {{
    width: 100%; padding: 6px 10px; border-radius: 4px; border: 1px solid #3c4043;
    background: #35363a; color: #e8eaed; font-size: 12px;
    margin-top: 4px; outline: none; transition: border-color 0.12s;
    font-family: 'Segoe UI', sans-serif;
}}
.rp-input:focus {{ border-color: #8ab4f8; }}
textarea.rp-input {{ font-family: 'Segoe UI', sans-serif; }}
select.rp-input {{ font-family: 'Segoe UI', sans-serif; }}
::-webkit-scrollbar {{ width: 7px; }}
::-webkit-scrollbar-track {{ background: #202124; }}
::-webkit-scrollbar-thumb {{ background: #3c4043; border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: #5f6368; }}
</style>
</head>
<body>
<div class=""layout"">
<aside class=""sidebar"">
    <div class=""sidebar-header"">
        <img src=""/api/icon"" alt=""S"" style=""width:32px;height:32px;border-radius:8px"" onerror=""this.style.display='none'"">
        <div><h1>Sentinel</h1><div class=""version"" id=""version"">v2.3.1</div></div>
    </div>
    <nav class=""nav"" id=""sidebar-nav"">
        <div class=""nav-item active"" data-page=""overview"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><rect x=""3"" y=""3"" width=""7"" height=""7"" rx=""1""/><rect x=""14"" y=""3"" width=""7"" height=""7"" rx=""1""/><rect x=""3"" y=""14"" width=""7"" height=""7"" rx=""1""/><rect x=""14"" y=""14"" width=""7"" height=""7"" rx=""1""/></svg>
            Overview
        </div>
        <div class=""nav-item"" data-page=""events"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M12 8v4l3 3""/><circle cx=""12"" cy=""12"" r=""10""/></svg>
            Events
        </div>
        <div class=""nav-item"" data-page=""scan"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><circle cx=""11"" cy=""11"" r=""8""/><path d=""M21 21l-4.35-4.35""/></svg>
            System Scan
        </div>
        <div class=""nav-item"" data-page=""quarantine"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z""/></svg>
            Quarantine
        </div>
        <div class=""nav-item"" data-page=""report"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z""/><polyline points=""14 2 14 8 20 8""/><line x1=""16"" y1=""13"" x2=""8"" y2=""13""/><line x1=""16"" y1=""17"" x2=""8"" y2=""17""/></svg>
            Report to Police
        </div>
        <div class=""nav-item"" data-page=""safety"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z""/></svg>
            Safety
        </div>
        <div class=""nav-item"" data-page=""ops"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M22 12h-4l-3 9L9 3l-3 9H2""/></svg>
            Ops Metrics
        </div>
        <div class=""nav-item"" data-page=""modules"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><polygon points=""12 2 2 7 12 12 22 7 12 2""/><polyline points=""2 17 12 22 22 17""/><polyline points=""2 12 12 17 22 12""/></svg>
            Modules
        </div>
        <div class=""nav-item"" data-page=""tools"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><path d=""M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z""/></svg>
            Tools
        </div>
        <div class=""nav-item"" data-page=""about"">
            <svg viewBox=""0 0 24 24"" fill=""none"" stroke=""currentColor"" stroke-width=""2""><circle cx=""12"" cy=""12"" r=""10""/><path d=""M12 16v-4""/><path d=""M12 8h.01""/></svg>
            About
        </div>
    </nav>
</aside>
<main class=""main"">
    <header class=""header"">
        <h2 id=""page-title"">Overview</h2>
        <div class=""status-badge active"" id=""status-badge"">
            <div class=""status-dot""></div>
            <span id=""status-text"">Protection Active</span>
        </div>
    </header>
    <div class=""content"">
        <!-- OVERVIEW -->
        <div class=""page active"" id=""page-overview"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Service Status</div><div class=""card-value success"" id=""ov-status"">Active</div><div class=""card-sub"" id=""ov-monitors"">Loading...</div></div>
                <div class=""card""><div class=""card-label"">Detections Today</div><div class=""card-value"" id=""ov-detections"">0</div><div class=""card-sub"">Last 24 hours</div></div>
                <div class=""card""><div class=""card-label"">Events/sec</div><div class=""card-value"" id=""ov-rate"">0</div><div class=""card-sub"">Telemetry throughput</div></div>
                <div class=""card""><div class=""card-label"">Quarantined</div><div class=""card-value warning"" id=""ov-quarantine"">0</div><div class=""card-sub"">Files isolated</div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Recent Activity</h3><button class=""btn"" onclick=""refreshEvents()"">Refresh</button></div>
                <div class=""panel-body""><div class=""event-list"" id=""ov-events""><div class=""empty-state"">Loading events...</div></div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Detection Rate (last 60 ticks)</h3></div>
                <div class=""panel-body""><div class=""chart-container""><div class=""bar-chart"" id=""ov-chart""></div></div></div>
            </div>
        </div>

        <!-- EVENTS -->
        <div class=""page"" id=""page-events"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Live Event Stream</h3><span class=""card-sub"" id=""ev-count"">0 events</span></div>
                <div class=""panel-body""><div class=""event-list"" id=""ev-list""><div class=""empty-state"">Connecting...</div></div></div>
            </div>
        </div>

        <!-- SCAN -->
        <div class=""page"" id=""page-scan"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Scan Status</div><div class=""card-value"" id=""sc-status"">Idle</div><div class=""card-sub"" id=""sc-time"">No scan run yet</div></div>
                <div class=""card""><div class=""card-label"">Findings</div><div class=""card-value"" id=""sc-findings"">&mdash;</div><div class=""card-sub"" id=""sc-critical""></div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header"">
                    <h3>One-Time System Scan</h3>
                    <button class=""btn btn-primary"" id=""btn-scan"" onclick=""startScan()"">Run Full Scan</button>
                </div>
                <div class=""panel-body"">
                    <p style=""color:#9aa0a6;font-size:12px;margin-bottom:12px"">
                        Scans running processes, persistence mechanisms (Run keys, scheduled tasks, startup folder, services, IFEO, Winlogon),
                        certificate stores, LNK shortcuts, staging paths, and network state for indicators of compromise.
                    </p>
                    <div class=""scan-progress"" id=""scan-progress"" style=""display:none"">
                        <div class=""progress-bar""><div class=""progress-fill"" id=""scan-bar"" style=""width:0%""></div></div>
                    </div>
                    <div class=""findings-grid"" id=""scan-findings""></div>
                </div>
            </div>
        </div>

        <!-- QUARANTINE -->
        <div class=""page"" id=""page-quarantine"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Quarantined Files</h3><button class=""btn"" onclick=""loadQuarantine()"">Refresh</button></div>
                <div class=""panel-body""><div id=""q-list""><div class=""empty-state"">Loading...</div></div></div>
            </div>
        </div>

        <!-- OPS -->
        <div class=""page"" id=""page-ops"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Pipeline Metrics</h3><button class=""btn"" onclick=""loadOps()"">Refresh</button></div>
                <div class=""panel-body""><div class=""metric-grid"" id=""ops-grid""><div class=""empty-state"">Loading metrics...</div></div></div>
            </div>
        </div>

        <!-- REPORT TO POLICE -->
        <div class=""page"" id=""page-report"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Evidence Packs</div><div class=""card-value"" id=""rp-pack-count"">0</div><div class=""card-sub"">Sealed incident packs</div></div>
                <div class=""card""><div class=""card-label"">Integrity</div><div class=""card-value success"" id=""rp-integrity"">&mdash;</div><div class=""card-sub"">SHA-256 manifest + HMAC</div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Evidence Packs</h3><button class=""btn"" onclick=""loadReportPacks()"">Refresh</button></div>
                <div class=""panel-body""><div id=""rp-packs""><div class=""empty-state"">Loading...</div></div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>File with Law Enforcement</h3></div>
                <div class=""panel-body"">
                    <p style=""color:#9aa0a6;font-size:12px;margin-bottom:14px"">
                        Sentinel prepares sealed evidence for you. It does NOT submit complaints to INTERPOL, IC3, or any police API.
                        Fill in your details, save the affidavit, then use your national cybercrime portal to file.
                    </p>
                    <div class=""metric-grid"" style=""margin-bottom:14px"">
                        <div class=""metric""><div class=""metric-label"">Full Name *</div><input type=""text"" id=""rp-name"" class=""rp-input"" placeholder=""Your legal name""></div>
                        <div class=""metric""><div class=""metric-label"">Email</div><input type=""text"" id=""rp-email"" class=""rp-input"" placeholder=""email@example.com""></div>
                        <div class=""metric""><div class=""metric-label"">Phone</div><input type=""text"" id=""rp-phone"" class=""rp-input"" placeholder=""+385...""></div>
                        <div class=""metric""><div class=""metric-label"">Address</div><input type=""text"" id=""rp-address"" class=""rp-input"" placeholder=""Street, City, Country""></div>
                        <div class=""metric""><div class=""metric-label"">National ID</div><input type=""text"" id=""rp-nationalid"" class=""rp-input"" placeholder=""OIB / SSN / etc.""></div>
                        <div class=""metric""><div class=""metric-label"">I am the...</div><select id=""rp-relationship"" class=""rp-input""><option>owner</option><option>authorized user</option><option>administrator</option><option>other</option></select></div>
                    </div>
                    <div style=""margin-bottom:14px"">
                        <div class=""metric-label"" style=""margin-bottom:4px"">Narrative (what happened)</div>
                        <textarea id=""rp-narrative"" class=""rp-input"" rows=""4"" placeholder=""Describe the incident..."" style=""width:100%;resize:vertical""></textarea>
                    </div>
                    <div class=""metric-grid"" style=""margin-bottom:14px"">
                        <div class=""metric""><div class=""metric-label"">Financial Loss</div><input type=""text"" id=""rp-loss"" class=""rp-input"" placeholder=""e.g. 500 EUR""></div>
                        <div class=""metric""><div class=""metric-label"">Data Affected</div><input type=""text"" id=""rp-data"" class=""rp-input"" placeholder=""e.g. passwords, photos""></div>
                        <div class=""metric""><div class=""metric-label"">Other Harm</div><input type=""text"" id=""rp-harm"" class=""rp-input"" placeholder=""e.g. emotional distress""></div>
                    </div>
                    <div style=""margin-bottom:14px;font-size:12px;color:#9aa0a6"">
                        <label style=""display:block;margin-bottom:5px;cursor:pointer""><input type=""checkbox"" id=""rp-consent1""> I want to file a formal complaint with law enforcement / the national portal.</label>
                        <label style=""display:block;margin-bottom:5px;cursor:pointer""><input type=""checkbox"" id=""rp-consent2""> I authorize investigators to examine this evidence pack and quarantined samples.</label>
                        <label style=""display:block;margin-bottom:5px;cursor:pointer""><input type=""checkbox"" id=""rp-consent3""> I understand false statements to authorities may be a criminal offense.</label>
                    </div>
                    <div style=""display:flex;gap:8px;flex-wrap:wrap"">
                        <button class=""btn btn-primary"" onclick=""saveAffidavit()"">Save Affidavit</button>
                        <button class=""btn"" style=""background:#81c995;border-color:#81c995;color:#202124;font-weight:600"" onclick=""sendReport()"">Send Report to Police</button>
                        <button class=""btn"" onclick=""openPackFolder()"">Open Pack Folder</button>
                        <button class=""btn"" onclick=""verifyIntegrity()"">Verify Integrity</button>
                    </div>
                    <div id=""rp-status"" style=""margin-top:8px;font-size:11px;color:#9aa0a6""></div>
                </div>
            </div>
        </div>

        <!-- SAFETY -->
        <div class=""page"" id=""page-safety"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Digital Coercion Defense</h3></div>
                <div class=""panel-body"">
                    <p style=""color:#9aa0a6;font-size:12px;margin-bottom:14px"">
                        Sentinel does not identify people as offenders and does not read your chats.
                        It watches THIS Windows PC for tools predators and stalkers often use:
                    </p>
                    <div class=""metric-grid"" style=""margin-bottom:14px"">
                        <div class=""metric""><div class=""metric-label"">Remote Control</div><div class=""metric-value"" style=""font-size:12px"">RATs, abused AnyDesk/TeamViewer, reverse shells</div></div>
                        <div class=""metric""><div class=""metric-label"">Covert Surveillance</div><div class=""metric-value"" style=""font-size:12px"">Screen/camera/input capture + persistence</div></div>
                        <div class=""metric""><div class=""metric-label"">Session Theft</div><div class=""metric-value"" style=""font-size:12px"">Browser, messaging, email, social, games, banking</div></div>
                        <div class=""metric""><div class=""metric-label"">Extortion Malware</div><div class=""metric-value"" style=""font-size:12px"">Exfiltration + C2 chains</div></div>
                    </div>
                    <p style=""color:#9aa0a6;font-size:12px;margin-bottom:14px"">
                        When a multi-signal chain confirms, Sentinel kills/quarantines and writes a sealed evidence pack.
                    </p>
                    <div class=""panel"" style=""background:#35363a;margin-bottom:14px"">
                        <div class=""panel-header""><h3 style=""color:#fdd663"">What You Should Still Do</h3></div>
                        <div class=""panel-body"" style=""font-size:12px;color:#9aa0a6"">
                            <ol style=""padding-left:18px;margin:0"">
                                <li style=""margin-bottom:5px"">Revoke sessions on important accounts (email, messaging, social, bank).</li>
                                <li style=""margin-bottom:5px"">Turn on 2FA everywhere you can.</li>
                                <li style=""margin-bottom:5px"">Block and report abusers on the platform.</li>
                                <li style=""margin-bottom:5px"">Use Report to Police with a sealed pack for device crimes.</li>
                                <li style=""margin-bottom:5px"">If you are in danger offline, contact emergency services.</li>
                            </ol>
                        </div>
                    </div>
                    <div class=""panel"" style=""background:rgba(129,201,149,0.06);border-color:#81c995"">
                        <div class=""panel-header""><h3 style=""color:#81c995"">Hardening Status</h3></div>
                        <div class=""panel-body"">
                            <p style=""font-size:12px;color:#9aa0a6;margin-bottom:10px"">
                                <strong style=""color:#81c995"">&#x2713; Always active</strong> - IPSec port lockdown, ASR Block rules,
                                RPC/DCOM firewall, credential hardening (LSASS PPL, WDigest off), registry hardening,
                                and browser hardening are enforced on every startup with no config gate.
                            </p>
                            <p style=""font-size:10px;color:#9aa0a6;margin-top:6px"">
                                Hardening cannot be disabled. It is always active as of Sentinel v2.5.5.
                            </p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- TOOLS -->
        <div class=""page"" id=""page-tools"">
            <div class=""panel"">
                <div class=""panel-header""><h3>Quick Access</h3></div>
                <div class=""panel-body"">
                    <div class=""metric-grid"">
                        <div class=""metric""><div class=""metric-label"">Data Folder</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">%ProgramData%\Sentinel</div></div>
                        <div class=""metric""><div class=""metric-label"">Event Log</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">%ProgramData%\Sentinel\events.jsonl</div></div>
                        <div class=""metric""><div class=""metric-label"">Quarantine</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">%ProgramData%\Sentinel\Quarantine</div></div>
                        <div class=""metric""><div class=""metric-label"">Evidence Packs</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">%ProgramData%\Sentinel\IncidentReports</div></div>
                        <div class=""metric""><div class=""metric-label"">Install Folder</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">C:\Program Files (x86)\Sentinel</div></div>
                        <div class=""metric""><div class=""metric-label"">Startup Trace</div><div class=""metric-value"" style=""font-size:11px;font-family:Consolas,monospace"">%ProgramData%\Sentinel\startup_trace.log</div></div>
                    </div>
                </div>
            </div>
            <div class=""panel"">
                <div class=""panel-header""><h3>Diagnostics</h3><button class=""btn"" onclick=""refreshDiagnostics()"">Refresh</button></div>
                <div class=""panel-body""><pre id=""tools-diag"" style=""font-size:11px;color:#9aa0a6;white-space:pre-wrap;margin:0"">Loading...</pre></div>
            </div>
        </div>

        <!-- MODULES -->
        <div class=""page"" id=""page-modules"">
            <div class=""cards"">
                <div class=""card""><div class=""card-label"">Total Modules</div><div class=""card-value"" id=""mod-total"">0</div><div class=""card-sub"" id=""mod-proc-name"">Select process</div></div>
                <div class=""card""><div class=""card-label"">Valid Signed</div><div class=""card-value success"" id=""mod-signed"">0</div><div class=""card-sub"" id=""mod-ms-signed"">0 Microsoft</div></div>
                <div class=""card""><div class=""card-label"">Unsigned / Custom</div><div class=""card-value warning"" id=""mod-unsigned"">0</div><div class=""card-sub"">Third-party / Local</div></div>
                <div class=""card""><div class=""card-label"">Anomalies / Foreign</div><div class=""card-value danger"" id=""mod-anomalies"">0</div><div class=""card-sub"" id=""mod-mem-anomalies"">0 in-memory</div></div>
            </div>
            <div class=""panel"">
                <div class=""panel-header"">
                    <div style=""display:flex;align-items:center;gap:12px;flex-wrap:wrap;flex:1"">
                        <select id=""mod-proc-select"" class=""rp-input"" style=""width:auto;min-width:240px;margin-top:0"" onchange=""auditSelectedProcess()"">
                            <option value="""">Select running process...</option>
                        </select>
                        <input id=""mod-filter"" class=""rp-input"" placeholder=""Filter modules by name or path..."" style=""width:auto;min-width:200px;margin-top:0"" onkeyup=""filterModuleTable()"">
                        <select id=""mod-status-filter"" class=""rp-input"" style=""width:auto;min-width:140px;margin-top:0"" onchange=""filterModuleTable()"">
                            <option value=""all"">All Modules</option>
                            <option value=""suspicious"">Suspicious Only</option>
                            <option value=""unsigned"">Unsigned Only</option>
                            <option value=""anomalies"">Memory Anomalies Only</option>
                        </select>
                    </div>
                    <div style=""display:flex;gap:8px"">
                        <button class=""btn"" onclick=""loadModuleProcesses()"">Refresh Procs</button>
                        <button class=""btn btn-primary"" onclick=""auditSelectedProcess()"">Audit Now</button>
                    </div>
                </div>
                <div class=""panel-body"" style=""padding:0"">
                    <div id=""mod-memory-alerts"" style=""padding:12px 16px;border-bottom:1px solid #3c4043;display:none""></div>
                    <div style=""overflow-x:auto;max-height:520px;overflow-y:auto"">
                        <table style=""width:100%;border-collapse:collapse;font-size:12px;text-align:left"" id=""mod-table"">
                            <thead>
                                <tr style=""background:#303135;color:#9aa0a6;border-bottom:1px solid #3c4043"">
                                    <th style=""padding:10px 14px"">Module Name</th>
                                    <th style=""padding:10px 14px"">Publisher / Signer</th>
                                    <th style=""padding:10px 14px"">Base Address</th>
                                    <th style=""padding:10px 14px"">Size</th>
                                    <th style=""padding:10px 14px"">Sentinel Verdict</th>
                                    <th style=""padding:10px 14px"">Full Path</th>
                                    <th style=""padding:10px 14px"">Action</th>
                                </tr>
                            </thead>
                            <tbody id=""mod-tbody"">
                                <tr><td colspan=""7"" style=""padding:30px;text-align:center;color:#9aa0a6"">Select a running process above and click Audit Now</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- ABOUT -->
        <div class=""page"" id=""page-about"">
            <div class=""panel"">
                <div class=""panel-header""><h3>About Sentinel</h3></div>
                <div class=""panel-body"">
                    <p style=""margin-bottom:12px;font-size:13px""><strong>Sentinel</strong> is a userland IDS/EDR for Windows built to battle hackers on machines people actually use.</p>
                    <div class=""metric-grid"">
                        <div class=""metric""><div class=""metric-label"">Architecture</div><div class=""metric-value"" style=""font-size:13px"">Two-process (Service + Agent)</div></div>
                        <div class=""metric""><div class=""metric-label"">Framework</div><div class=""metric-value"" style=""font-size:13px"">.NET Framework 4.8</div></div>
                        <div class=""metric""><div class=""metric-label"">Platform</div><div class=""metric-value"" style=""font-size:13px"">Windows x64</div></div>
                        <div class=""metric""><div class=""metric-label"">License</div><div class=""metric-value"" style=""font-size:13px"">MIT</div></div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</main>
</div>
<script>
// 
// Sentinel Dashboard - IE11-compatible JavaScript (ES5 only)
// No arrow functions, no const/let, no template literals, no fetch,
// no async/await, no URLSearchParams, no Array.from needed.
// 

var API = '';
var CSRF = '';
var ws = null;
var eventBuffer = [];
var chartData = [];
var chartIdx = 0;
var scanPolling = null;
var TOKEN = '';
var wsRetries = 0;
var eventPollInterval = null;

// Initialize chart data
(function() {{
    for (var i = 0; i < 60; i++) chartData.push(0);
}})();

// v2.2.0: token arrives via tray launch URL (?token=), then lives in sessionStorage.
// v2.3.1: server embeds current token in HTML (EMBEDDED_TOKEN) so page refresh always works.
function getToken() {{
    try {{
        // 1. Prefer server-embedded token (always current after agent restart)
        if (typeof EMBEDDED_TOKEN === 'string' && EMBEDDED_TOKEN.length > 0) {{
            try {{ sessionStorage.setItem('sentinel_token', EMBEDDED_TOKEN); }} catch(e) {{}}
            return EMBEDDED_TOKEN;
        }}
        // 2. URL ?token= param (tray icon launch)
        var search = window.location.search;
        var match = search.match(/[?&]token=([^&]*)/);
        if (match) {{
            var t = decodeURIComponent(match[1]);
            try {{ sessionStorage.setItem('sentinel_token', t); }} catch(e) {{}}
            // Strip token from URL
            var clean = search.replace(/([?&])token=[^&]*/, '$1').replace(/^[?&]/, '?').replace(/[?&]$/, '');
            try {{ history.replaceState({{}}, '', window.location.pathname + clean + window.location.hash); }} catch(e) {{}}
            return t;
        }}
        // 3. Fallback to sessionStorage (stale after restart - will 401)
        try {{ return sessionStorage.getItem('sentinel_token') || ''; }} catch(e) {{ return ''; }}
    }} catch (e) {{ return ''; }}
}}
TOKEN = getToken();

//  XHR-based API helper (IE11 compatible) 
function apiCall(path, opts, callback) {{
    opts = opts || {{}};
    var method = opts.method || 'GET';
    var xhr = new XMLHttpRequest();
    xhr.open(method, API + path, true);
    xhr.setRequestHeader('Authorization', 'Bearer ' + TOKEN);
    if (opts.headers) {{
        for (var key in opts.headers) {{
            if (opts.headers.hasOwnProperty(key)) {{
                xhr.setRequestHeader(key, opts.headers[key]);
            }}
        }}
    }}
    xhr.onreadystatechange = function() {{
        if (xhr.readyState === 4) {{
            if (xhr.status === 401) {{
                document.getElementById('ov-events').innerHTML = '<div class=""empty-state"" style=""color:#f28b82"">Authentication failed. Reopen dashboard from the Sentinel tray icon.</div>';
                return;
            }}
            var data = null;
            try {{ data = JSON.parse(xhr.responseText); }} catch(e) {{ data = {{ ok: false, error: 'Parse error' }}; }}
            if (callback) callback(data);
        }}
    }};
    xhr.onerror = function() {{
        if (callback) callback({{ ok: false, error: 'Network error' }});
    }};
    if (opts.body) {{
        xhr.send(opts.body);
    }} else {{
        xhr.send();
    }}
}}

//  XSS-safe HTML encoding 
function esc(s) {{
    if (s == null) return '';
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(String(s)));
    return d.innerHTML;
}}

//  Navigation 
(function() {{
    var navItems = document.getElementById('sidebar-nav').getElementsByClassName('nav-item');
    var pages = document.getElementsByClassName('page');

    function handleNavClick(idx) {{
        return function() {{
            var i;
            for (i = 0; i < navItems.length; i++) {{
                navItems[i].className = 'nav-item';
            }}
            for (i = 0; i < pages.length; i++) {{
                pages[i].className = 'page';
            }}
            navItems[idx].className = 'nav-item active';
            var page = navItems[idx].getAttribute('data-page');
            var pageEl = document.getElementById('page-' + page);
            if (pageEl) pageEl.className = 'page active';
            document.getElementById('page-title').textContent = navItems[idx].textContent.replace(/^\s+|\s+$/g, '');
            // Load page-specific data
            if (page === 'events') loadEventHistory();
            if (page === 'ops') loadOps();
            if (page === 'quarantine') loadQuarantine();
            if (page === 'scan') checkScanStatus();
            if (page === 'report') loadReportPacks();
            if (page === 'safety') checkHardenedMode();
            if (page === 'tools') refreshDiagnostics();
            if (page === 'modules') loadModuleAuditor();
        }};
    }}

    for (var i = 0; i < navItems.length; i++) {{
        navItems[i].onclick = handleNavClick(i);
    }}
}})();

//  CSRF helper 
function ensureCsrf(callback) {{
    if (CSRF) {{ callback(CSRF); return; }}
    apiCall('/api/csrf', {{}}, function(d) {{
        CSRF = (d && d.token) ? d.token : '';
        callback(CSRF);
    }});
}}

//  Status 
function loadStatus() {{
    apiCall('/api/status', {{}}, function(data) {{
        if (data && data.ok) {{
            document.getElementById('version').textContent = 'v' + data.version;
            var badge = document.getElementById('status-badge');
            var text = document.getElementById('status-text');
            if (data.serviceRunning) {{
                badge.className = 'status-badge active';
                text.textContent = 'Protection Active';
                document.getElementById('ov-status').textContent = 'Active';
                document.getElementById('ov-status').className = 'card-value success';
            }} else {{
                badge.className = 'status-badge inactive';
                text.textContent = 'Service Stopped';
                document.getElementById('ov-status').textContent = 'Stopped';
                document.getElementById('ov-status').className = 'card-value danger';
            }}
        }}
    }});
    apiCall('/api/health', {{}}, function(health) {{
        if (health && health.ok) {{
            document.getElementById('ov-monitors').textContent =
                health.monitorsRunning + '/' + health.monitorsRegistered + ' monitors running';
        }}
    }});
}}

//  Events 
function refreshEvents() {{
    apiCall('/api/events?count=20', {{}}, function(data) {{
        if (data && data.ok) {{
            renderEvents(data.events, 'ov-events');
            var detCount = 0;
            if (data.events) {{
                for (var i = 0; i < data.events.length; i++) {{
                    if (data.events[i].type === 'detection') detCount++;
                }}
            }}
            document.getElementById('ov-detections').textContent = detCount;
        }}
    }});
}}

function renderEvents(events, containerId) {{
    var container = document.getElementById(containerId);
    if (!events || events.length === 0) {{
        container.innerHTML = '<div class=""empty-state"">No events recorded yet</div>';
        return;
    }}
    var html = '';
    for (var i = 0; i < events.length; i++) {{
        var ev = events[i];
        var parsed;
        try {{ parsed = JSON.parse(ev.data || JSON.stringify(ev)); }} catch(e) {{ parsed = ev; }}
        var type = parsed.type || ev.type || 'info';
        var ts = parsed.timestamp || ev.timestamp || '';
        var title = '', detail = '';
        if (parsed.data) {{
            var d = parsed.data;
            title = d.RuleName || d.ActionTaken || type;
            detail = d.ProcessName ? (d.ProcessName + ' (PID ' + d.ProcessId + ')') : (d.Evidence || '');
        }} else {{
            title = type;
        }}
        var iconClass = type === 'detection' ? 'detection' : type === 'response' ? 'response' : 'info';
        var icon = type === 'detection' ? '!' : type === 'response' ? '\u2713' : '\u2022';
        var timeStr = '';
        if (ts) {{ try {{ timeStr = new Date(ts).toLocaleTimeString(); }} catch(e) {{}} }}
        html += '<div class=""event-item""><div class=""event-icon ' + iconClass + '"">' + icon + '</div><div class=""event-body""><div class=""event-title"">' + esc(title) + '</div><div class=""event-detail"">' + esc(detail) + '</div></div><div class=""event-time"">' + esc(timeStr) + '</div></div>';
    }}
    container.innerHTML = html;
}}

// Load recent event history into the buffer (used on WS open and page show).
function loadEventHistory() {{
    apiCall('/api/events?count=50', {{}}, function(data) {{
        var evList = document.getElementById('ev-list');
        if (data && data.ok && data.events && data.events.length > 0) {{
            // /api/events returns newest-first; seed the buffer with raw JSON lines.
            eventBuffer = [];
            for (var i = 0; i < data.events.length; i++) {{
                var raw = data.events[i].data || JSON.stringify(data.events[i]);
                eventBuffer.push(raw);
            }}
            if (eventBuffer.length > 200) eventBuffer = eventBuffer.slice(0, 200);
            var mapped = [];
            for (var j = 0; j < eventBuffer.slice(0, 50).length; j++) mapped.push({{ data: eventBuffer[j], type: 'info' }});
            renderEvents(mapped, 'ev-list');
            document.getElementById('ev-count').textContent = eventBuffer.length + ' events';
        }} else if (eventBuffer.length === 0) {{
            evList.innerHTML = '<div class=""empty-state"">Connected \u2014 waiting for events...</div>';
        }}
    }});
}}

//  WebSocket 
function connectWs() {{
    try {{
        if (!window.WebSocket) {{ startEventPolling(); return; }}
        ws = new WebSocket('ws://localhost:19845/ws/events?token=' + encodeURIComponent(TOKEN));
        ws.onopen = function() {{
            wsRetries = 0;
            // The WebSocket only streams events that arrive AFTER connect. Seed the
            // buffer with recent history so the Events page isn't empty on open.
            loadEventHistory();
        }};
        ws.onmessage = function(msg) {{
            eventBuffer.unshift(msg.data);
            if (eventBuffer.length > 200) eventBuffer.pop();
            var evList = document.getElementById('ev-list');
            var pageEvents = document.getElementById('page-events');
            if (pageEvents.className.indexOf('active') >= 0) {{
                var events = eventBuffer.slice(0, 50);
                var mapped = [];
                for (var i = 0; i < events.length; i++) mapped.push({{ data: events[i], type: 'info' }});
                renderEvents(mapped, 'ev-list');
                document.getElementById('ev-count').textContent = eventBuffer.length + ' events';
            }}
            try {{
                var parsed = JSON.parse(msg.data);
                if (parsed.type === 'detection') chartData[chartIdx % 60]++;
            }} catch(e) {{}}
        }};
        ws.onclose = function() {{
            wsRetries++;
            if (wsRetries > 3) {{ startEventPolling(); }}
            else {{ setTimeout(connectWs, 3000); }}
        }};
        ws.onerror = function() {{ if (ws) ws.close(); }};
    }} catch(e) {{
        wsRetries++;
        if (wsRetries > 3) startEventPolling();
        else setTimeout(connectWs, 3000);
    }}
}}

function startEventPolling() {{
    document.getElementById('ev-list').innerHTML = '<div class=""empty-state"">Live polling (WebSocket unavailable)...</div>';
    if (eventPollInterval) return;
    eventPollInterval = setInterval(function() {{
        apiCall('/api/events?count=30', {{}}, function(data) {{
            if (data && data.ok && data.events) {{
                var pageEvents = document.getElementById('page-events');
                if (pageEvents.className.indexOf('active') >= 0) {{
                    renderEvents(data.events, 'ev-list');
                    document.getElementById('ev-count').textContent = data.events.length + ' events (polling)';
                }}
            }}
        }});
    }}, 3000);
}}

//  Chart 
function updateChart() {{
    var container = document.getElementById('ov-chart');
    var max = 1;
    for (var i = 0; i < chartData.length; i++) {{ if (chartData[i] > max) max = chartData[i]; }}
    var html = '';
    for (var j = 0; j < chartData.length; j++) {{
        var h = Math.max(2, (chartData[j] / max) * 100);
        html += '<div class=""bar"" style=""height:' + h + '%"" title=""' + chartData[j] + '""></div>';
    }}
    container.innerHTML = html;
    chartIdx++;
    chartData[chartIdx % 60] = 0;
}}

//  Ops 
function loadOps() {{
    apiCall('/api/ops', {{}}, function(data) {{
        var grid = document.getElementById('ops-grid');
        if (data && (data.ok || data.ops)) {{
            var ops = data.ops || data;
            var telRecv = ops.TelemetryReceived || ops.telemetryReceived || 0;
            var telDrop = ops.TelemetryDropped || ops.telemetryDropped || 0;
            var dropRate = telRecv > 0 ? ((telDrop / telRecv) * 100).toFixed(2) : '0.00';
            var metrics = [
                ['Telemetry/sec', ops.TelemetryPerSecond || ops.telemetryPerSecond || 0],
                ['Detections/sec', ops.DetectionsPerSecond || ops.detectionsPerSecond || 0],
                ['Detections Total', ops.DetectionsTotal || ops.detectionsTotal || 0],
                ['Responses Total', ops.ResponsesTotal || ops.responsesTotal || 0],
                ['Drop Rate', dropRate + '%'],
                ['Correlation P50', (ops.CorrelationLatencyMsP50 || ops.correlationLatencyMsP50 || 0) + 'ms'],
                ['Monitors', (ops.RunningMonitors || ops.runningMonitors || 0) + '/' + (ops.RegisteredMonitors || ops.registeredMonitors || 0)],
                ['Plugins', ops.PluginCount || ops.pluginCount || 0],
                ['Weighted Correlation', (ops.WeightedCorrelationEnabled || ops.weightedCorrelationEnabled) ? 'Enabled' : 'Disabled'],
                ['Product Version', ops.ProductVersion || ops.productVersion || '\u2014']
            ];
            var html = '';
            for (var i = 0; i < metrics.length; i++) {{
                html += '<div class=""metric""><div class=""metric-label"">' + esc(metrics[i][0]) + '</div><div class=""metric-value"">' + esc(String(metrics[i][1])) + '</div></div>';
            }}
            grid.innerHTML = html;
            document.getElementById('ov-rate').textContent = ops.TelemetryPerSecond || ops.telemetryPerSecond || 0;
        }} else {{
            grid.innerHTML = '<div class=""empty-state"">Unable to reach Sentinel Service</div>';
        }}
    }});
}}

//  Quarantine 
function loadQuarantine() {{
    apiCall('/api/quarantine', {{}}, function(data) {{
        var container = document.getElementById('q-list');
        if (data && data.ok && data.items && data.items.length > 0) {{
            var html = '';
            for (var i = 0; i < data.items.length; i++) {{
                var item = data.items[i];
                var name = item.OriginalName || item.originalName || item.Name || 'Unknown';
                var path = item.OriginalPath || item.originalPath || '';
                var date = item.QuarantinedAt || item.quarantinedAt || '';
                var dateStr = '';
                if (date) {{ try {{ dateStr = new Date(date).toLocaleDateString(); }} catch(e) {{}} }}
                html += '<div class=""quarantine-item""><div><div style=""font-weight:500"">' + esc(name) + '</div><div class=""q-path"">' + esc(path) + '</div></div><div class=""event-time"">' + esc(dateStr) + '</div></div>';
            }}
            container.innerHTML = html;
            document.getElementById('ov-quarantine').textContent = data.items.length;
        }} else {{
            container.innerHTML = '<div class=""empty-state"">No files in quarantine</div>';
            document.getElementById('ov-quarantine').textContent = '0';
        }}
    }});
}}

//  Scan 
function startScan() {{
    var btn = document.getElementById('btn-scan');
    btn.disabled = true;
    btn.textContent = 'Scanning...';
    document.getElementById('scan-progress').style.display = 'block';
    document.getElementById('scan-bar').style.width = '30%';
    document.getElementById('sc-status').textContent = 'Running';
    document.getElementById('sc-status').className = 'card-value warning';

    ensureCsrf(function(token) {{
        apiCall('/api/scan', {{ method: 'POST', headers: {{ 'X-CSRF-Token': token }} }}, function() {{
            scanPolling = setInterval(checkScanStatus, 2000);
        }});
    }});
}}

function checkScanStatus() {{
    apiCall('/api/scan/status', {{}}, function(data) {{
        if (!data || !data.ok) return;
        var btn = document.getElementById('btn-scan');
        if (data.status === 'running') {{
            document.getElementById('scan-progress').style.display = 'block';
            document.getElementById('scan-bar').style.width = '60%';
            document.getElementById('sc-status').textContent = 'Running';
            document.getElementById('sc-status').className = 'card-value warning';
            btn.disabled = true;
            btn.textContent = 'Scanning...';
        }} else if (data.status === 'completed' && data.result) {{
            if (scanPolling) {{ clearInterval(scanPolling); scanPolling = null; }}
            var r = data.result;
            document.getElementById('scan-progress').style.display = 'none';
            document.getElementById('sc-status').textContent = 'Complete';
            document.getElementById('sc-status').className = 'card-value success';
            document.getElementById('sc-time').textContent = 'Duration: ' + (r.DurationMs || r.durationMs || 0) + 'ms';
            var findings = r.Findings || r.findings || [];
            document.getElementById('sc-findings').textContent = findings.length;
            var critical = 0, high = 0;
            for (var i = 0; i < findings.length; i++) {{
                var sev = findings[i].Severity || findings[i].severity || 0;
                if (sev >= 4) critical++;
                else if (sev === 3) high++;
            }}
            document.getElementById('sc-critical').textContent = critical + ' critical, ' + high + ' high';
            if (critical > 0) document.getElementById('sc-findings').className = 'card-value danger';
            else if (high > 0) document.getElementById('sc-findings').className = 'card-value warning';
            else document.getElementById('sc-findings').className = 'card-value success';

            var container = document.getElementById('scan-findings');
            if (findings.length === 0) {{
                container.innerHTML = '<div class=""empty-state"" style=""padding:20px"">No threats found. System appears clean.</div>';
            }} else {{
                findings.sort(function(a, b) {{ return (b.Severity || b.severity || 0) - (a.Severity || a.severity || 0); }});
                var html = '';
                for (var j = 0; j < findings.length; j++) {{
                    var f = findings[j];
                    var s = f.Severity || f.severity || 0;
                    var sevClass = s >= 4 ? 'critical' : s === 3 ? 'high' : s === 2 ? 'medium' : 'low';
                    html += '<div class=""finding""><div class=""finding-severity ' + sevClass + '""></div><div class=""finding-body""><div class=""finding-title"">' + esc(f.Title || f.title) + '</div><div class=""finding-desc"">' + esc(f.Description || f.description) + '</div></div></div>';
                }}
                container.innerHTML = html;
            }}
            btn.disabled = false;
            btn.textContent = 'Run Full Scan';
        }} else {{
            btn.disabled = false;
            btn.textContent = 'Run Full Scan';
        }}
    }});
}}

//  Report to Police 
function loadReportPacks() {{
    apiCall('/api/packs', {{}}, function(data) {{
        var container = document.getElementById('rp-packs');
        if (data && data.ok && data.packs && data.packs.length > 0) {{
            document.getElementById('rp-pack-count').textContent = data.packs.length;
            var html = '';
            for (var i = 0; i < data.packs.length; i++) {{
                var p = data.packs[i];
                var created = '';
                try {{ created = new Date(p.created).toLocaleString(); }} catch(e) {{}}
                html += '<div class=""finding""><div class=""finding-severity critical""></div><div class=""finding-body""><div class=""finding-title"">' + esc(p.name) + '</div><div class=""finding-desc"">' + p.fileCount + ' files | Created: ' + esc(created) + ' | Manifest: ' + (p.hasManifest ? 'Sealed' : 'Missing') + '</div></div></div>';
            }}
            container.innerHTML = html;
            var allSealed = true;
            for (var j = 0; j < data.packs.length; j++) {{ if (!data.packs[j].hasManifest) allSealed = false; }}
            document.getElementById('rp-integrity').textContent = allSealed ? 'Sealed' : 'Partial';
            document.getElementById('rp-integrity').className = allSealed ? 'card-value success' : 'card-value warning';
        }} else {{
            container.innerHTML = '<div class=""empty-state"">No evidence packs yet. Packs are created when Sentinel confirms a multi-signal attack chain.</div>';
            document.getElementById('rp-pack-count').textContent = '0';
        }}
        loadReportPrefs();
    }});
}}

function loadReportPrefs() {{
    apiCall('/api/report/prefs', {{}}, function(data) {{
        if (data && data.ok && data.prefs) {{
            var p = data.prefs;
            if (p.FullName || p.fullName) document.getElementById('rp-name').value = p.FullName || p.fullName || '';
            if (p.Email || p.email) document.getElementById('rp-email').value = p.Email || p.email || '';
            if (p.Phone || p.phone) document.getElementById('rp-phone').value = p.Phone || p.phone || '';
            if (p.Address || p.address) document.getElementById('rp-address').value = p.Address || p.address || '';
            if (p.NationalId || p.nationalId) document.getElementById('rp-nationalid').value = p.NationalId || p.nationalId || '';
            if (p.AdditionalNarrative || p.additionalNarrative) document.getElementById('rp-narrative').value = p.AdditionalNarrative || p.additionalNarrative || '';
            if (p.FinancialLoss || p.financialLoss) document.getElementById('rp-loss').value = p.FinancialLoss || p.financialLoss || '';
            if (p.DataAffected || p.dataAffected) document.getElementById('rp-data').value = p.DataAffected || p.dataAffected || '';
            if (p.OtherHarm || p.otherHarm) document.getElementById('rp-harm').value = p.OtherHarm || p.otherHarm || '';
        }}
    }});
}}

function saveAffidavit() {{
    var prefs = {{
        FullName: document.getElementById('rp-name').value,
        Email: document.getElementById('rp-email').value,
        Phone: document.getElementById('rp-phone').value,
        Address: document.getElementById('rp-address').value,
        NationalId: document.getElementById('rp-nationalid').value,
        Relationship: document.getElementById('rp-relationship').value,
        AdditionalNarrative: document.getElementById('rp-narrative').value,
        FinancialLoss: document.getElementById('rp-loss').value,
        DataAffected: document.getElementById('rp-data').value,
        OtherHarm: document.getElementById('rp-harm').value
    }};
    ensureCsrf(function(token) {{
        apiCall('/api/report/save', {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': token }},
            body: JSON.stringify(prefs)
        }}, function(res) {{
            var status = document.getElementById('rp-status');
            if (res && res.ok) {{
                status.textContent = 'Affidavit saved at ' + new Date().toLocaleTimeString();
                status.style.color = '#81c995';
            }} else {{
                status.textContent = 'Failed to save: ' + ((res && res.error) || 'unknown');
                status.style.color = '#f28b82';
            }}
        }});
    }});
}}

function sendReport() {{
    var portals = {{
        'HR': 'https://epolicija.gov.hr/',
        'US': 'https://www.ic3.gov/',
        'UK': 'https://www.actionfraud.police.uk/',
        'DE': 'https://www.polizei.de/onlinewache',
        'AU': 'https://www.cyber.gov.au/report'
    }};
    var url = portals['HR'] || 'https://www.interpol.int/en/Contacts/Contact-INTERPOL';
    window.open(url, '_blank');
    openPackFolder();
}}

function openPackFolder() {{
    var status = document.getElementById('rp-status');
    status.textContent = 'Evidence packs: %ProgramData%\\Sentinel\\IncidentReports\\';
    status.style.color = '#8ab4f8';
}}

function verifyIntegrity() {{
    var status = document.getElementById('rp-status');
    status.textContent = 'Verifying...';
    status.style.color = '#9aa0a6';
    apiCall('/api/report/verify', {{}}, function(res) {{
        if (res && res.ok) {{
            status.textContent = res.message || 'All packs verified';
            status.style.color = '#81c995';
        }} else {{
            status.textContent = (res && res.error) || 'Verification failed';
            status.style.color = '#f28b82';
        }}
    }});
}}

//  Tools 
function refreshDiagnostics() {{
    apiCall('/api/diagnostics', {{}}, function(data) {{
        var pre = document.getElementById('tools-diag');
        if (data && data.ok) {{
            pre.textContent = data.text;
        }} else {{
            pre.textContent = 'Failed to load diagnostics: ' + ((data && data.error) || 'service unreachable');
        }}
    }});
}}

//  Modules Explorer 
var currentAuditModules = [];
var currentAuditAnomalies = [];
var currentAuditPid = 0;

function loadModuleAuditor() {{
    var sel = document.getElementById('mod-proc-select');
    if (sel && sel.options.length <= 1) {{
        loadModuleProcesses();
    }}
}}

function loadModuleProcesses() {{
    apiCall('/api/modules/processes', {{}}, function(data) {{
        var sel = document.getElementById('mod-proc-select');
        if (!sel) return;
        sel.innerHTML = '<option value="""">Select running process...</option>';
        if (data && data.ok && data.processes) {{
            for (var i = 0; i < data.processes.length; i++) {{
                var p = data.processes[i];
                var opt = document.createElement('option');
                opt.value = p.ProcessId;
                opt.textContent = p.ProcessName + ' (PID ' + p.ProcessId + ')' + (p.IsProtected ? ' [Protected]' : '');
                sel.appendChild(opt);
            }}
        }}
    }});
}}

function auditSelectedProcess() {{
    var sel = document.getElementById('mod-proc-select');
    if (!sel || !sel.value) return;
    var pid = parseInt(sel.value, 10);
    if (!pid || pid <= 0) return;
    currentAuditPid = pid;

    var tbody = document.getElementById('mod-tbody');
    tbody.innerHTML = '<tr><td colspan=""7"" style=""padding:30px;text-align:center;color:#8ab4f8"">Auditing process memory and loaded modules...</td></tr>';

    apiCall('/api/modules/audit?pid=' + pid, {{}}, function(data) {{
        if (!data || !data.ok || !data.audit) {{
            tbody.innerHTML = '<tr><td colspan=""7"" style=""padding:30px;text-align:center;color:#f28b82"">Audit failed: ' + ((data && data.error) || 'unknown error') + '</td></tr>';
            return;
        }}
        renderModuleAudit(data.audit);
    }});
}}

function renderModuleAudit(audit) {{
    document.getElementById('mod-total').textContent = audit.TotalModules;
    document.getElementById('mod-signed').textContent = audit.SignedModules;
    document.getElementById('mod-unsigned').textContent = audit.UnsignedModules;
    document.getElementById('mod-anomalies').textContent = audit.SuspiciousModules + audit.MemoryAnomalyCount;
    document.getElementById('mod-proc-name').textContent = audit.ProcessName + ' (PID ' + audit.ProcessId + ')';
    document.getElementById('mod-ms-signed').textContent = (audit.IsSigned ? 'Host signed (' + audit.Publisher + ')' : 'Host unsigned');
    document.getElementById('mod-mem-anomalies').textContent = audit.MemoryAnomalyCount + ' memory anomalies';

    currentAuditModules = audit.Modules || [];
    currentAuditAnomalies = audit.MemoryAnomalies || [];

    var alertBox = document.getElementById('mod-memory-alerts');
    if (currentAuditAnomalies.length > 0) {{
        var html = '<div style=""font-weight:600;color:#f28b82;margin-bottom:6px"">In-Memory Anomalies Detected (' + currentAuditAnomalies.length + ')</div>';
        for (var a = 0; a < currentAuditAnomalies.length; a++) {{
            var an = currentAuditAnomalies[a];
            html += '<div style=""margin-top:4px;padding:8px 12px;background:#3c2020;border-left:3px solid #f28b82;border-radius:2px;font-size:11px"">' +
                    '<strong>[' + esc(an.Severity) + '] ' + esc(an.AnomalyType) + '</strong> @ 0x' + an.BaseAddress.toString(16) + ' (' + an.ProtectionString + ', ' + an.TypeString + '): ' + esc(an.Description) +
                    '</div>';
        }}
        alertBox.innerHTML = html;
        alertBox.style.display = 'block';
    }} else {{
        alertBox.innerHTML = '';
        alertBox.style.display = 'none';
    }}

    filterModuleTable();
}}

function filterModuleTable() {{
    var tbody = document.getElementById('mod-tbody');
    var filterText = (document.getElementById('mod-filter').value || '').toLowerCase();
    var statusFilter = document.getElementById('mod-status-filter').value;

    var rows = [];
    for (var i = 0; i < currentAuditModules.length; i++) {{
        var m = currentAuditModules[i];
        if (filterText && m.Name.toLowerCase().indexOf(filterText) === -1 && m.Path.toLowerCase().indexOf(filterText) === -1) {{
            continue;
        }}
        if (statusFilter === 'suspicious' && m.Allowed) continue;
        if (statusFilter === 'unsigned' && m.IsSigned) continue;
        if (statusFilter === 'anomalies') continue;

        var signerBadge = m.IsSigned
            ? '<span style=""display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;background:rgba(129,201,149,0.15);color:#81c995"">' + esc(m.Publisher || 'Signed') + '</span>'
            : '<span style=""display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;background:rgba(154,160,166,0.15);color:#9aa0a6"">Unsigned</span>';

        var verdictBadge = m.Allowed
            ? '<span style=""display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;background:rgba(138,180,248,0.15);color:#8ab4f8"">Allowed: ' + esc(m.VerdictReason) + '</span>'
            : '<span style=""display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;background:rgba(242,139,130,0.15);color:#f28b82;font-weight:600"">Flagged: ' + esc(m.VerdictReason) + '</span>';

        var actionBtn = (!m.Allowed && m.Path)
            ? '<button class=""btn btn-danger"" style=""padding:3px 8px;font-size:10px"" onclick=""remediateModule(' + currentAuditPid + ', \'' + esc(m.Path).replace(/\\/g, '\\\\') + '\')"">Quarantine</button>'
            : '<span style=""color:#5f6368"">&mdash;</span>';

        rows.push('<tr style=""border-bottom:1px solid #35363a"">' +
            '<td style=""padding:8px 14px;font-weight:500;color:#e8eaed"">' + esc(m.Name) + '</td>' +
            '<td style=""padding:8px 14px"">' + signerBadge + '</td>' +
            '<td style=""padding:8px 14px;font-family:monospace;color:#9aa0a6"">' + esc(m.BaseAddressHex) + '</td>' +
            '<td style=""padding:8px 14px;color:#9aa0a6"">' + esc(m.SizeFormatted) + '</td>' +
            '<td style=""padding:8px 14px"">' + verdictBadge + '</td>' +
            '<td style=""padding:8px 14px;color:#9aa0a6;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"" title=""' + esc(m.Path) + '"">' + esc(m.Path) + '</td>' +
            '<td style=""padding:8px 14px"">' + actionBtn + '</td>' +
            '</tr>');
    }}

    if (rows.length === 0) {{
        tbody.innerHTML = '<tr><td colspan=""7"" style=""padding:30px;text-align:center;color:#9aa0a6"">' +
            (currentAuditModules.length === 0 ? 'No modules found or process exited.' : 'No modules match current filter.') +
            '</td></tr>';
    }} else {{
        tbody.innerHTML = rows.join('');
    }}
}}

function remediateModule(pid, path) {{
    if (!confirm('Contain and quarantine hostile module: ' + path + '?')) return;
    ensureCsrf(function(csrf) {{
        var body = JSON.stringify({{ pid: pid, path: path }});
        apiCall('/api/modules/remediate', {{
            method: 'POST',
            headers: {{ 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' }},
            body: body
        }}, function(res) {{
            if (res && res.ok) {{
                alert('Success: ' + (res.message || 'Module quarantined'));
                auditSelectedProcess();
            }} else {{
                alert('Remediation failed: ' + ((res && res.error) || 'error'));
            }}
        }});
    }});
}}

//  Init 
loadStatus();
refreshEvents();
connectWs();
loadQuarantine();
loadModuleProcesses();
setInterval(updateChart, 5000);
setInterval(loadStatus, 30000);
setInterval(refreshEvents, 15000);
</script>
</body>
</html>";
    }
}
