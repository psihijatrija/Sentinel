// v3.1.5: DefenseTamper rule was considered but deferred.
// Anti-tamper is out of scope for a userland EDR: an admin-level attacker
// can bypass it before Sentinel can react, and the installer path would
// generate false positives. Kept as an empty placeholder to avoid stale
// references in git history.
// See: Rules.Ransomware.cs, RawDiskAccessMonitor.cs for the v3.1.5 additions.
