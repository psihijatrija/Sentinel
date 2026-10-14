$ErrorActionPreference = 'SilentlyContinue'
$out = New-Object System.Collections.Generic.List[string]
try {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    $out.Add("set True at " + (Get-Date -Format HH:mm:ss))
    Start-Sleep -Seconds 25
    $out.Add("re-check at " + (Get-Date -Format HH:mm:ss))
    $r = Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled
    foreach ($p in $r) { $out.Add(("  {0,-10} Enabled={1}" -f $p.Name, $p.Enabled)) }
    $off = @($r | Where-Object { -not $_.Enabled }).Count
    $out.Add("profiles_off_after_25s: " + $off + " of 3")
} catch {
    $out.Add("ERROR in revert check: " + $_.Exception.Message)
}

try {
    $ev = Get-WinEvent -LogName 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' -MaxEvents 40 -ErrorAction Stop |
        Where-Object { $_.Id -in 2002, 2003 } | Select-Object -First 6
    if (-not $ev) { $out.Add("no 2002/2003 firewall events found") }
    foreach ($e in $ev) {
        $xml = [xml]$e.ToXml()
        $app = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'ModifyingApplication' }).'#text'
        $out.Add(("{0}  id={1}  app={2}" -f $e.TimeCreated.ToString('HH:mm:ss'), $e.Id, $app))
    }
} catch {
    $out.Add("ERROR reading firewall event log: " + $_.Exception.Message)
}

Set-Content -Path 'e:\Gorstak\Sentinel\_fwresult.txt' -Value $out -Encoding UTF8
