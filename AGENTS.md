# Sentinel Agent Guidelines

This repository follows strict architectural, workflow, and security rules:

1. **Workflow & Versioning**: Follow `.agents/rules/workflow.md` and `.kiro/steering/workflow.md`. Versions are strictly `MAJOR.MINOR.PATCH`, bumped by exactly one patch per release. Single source of truth is `version.txt`. Never jump versions. Releases use `installer/release.ps1` and `D:\Gorstak\push.ps1 -ProjectFilter sentinel`.
2. **Hard Constraints**: Follow `.agents/rules/constraints.md` and `.kiro/steering/constraints.md`. Userland only (no kernel drivers, no rootkits). Tier2 NEVER triggers response actions (LogOnly unconditionally). Observe-until-chain. Fail-closed. No string-built JSON. DI required everywhere.
3. **Git Rules**: Follow `.agents/rules/git-rules.md` and `.kiro/steering/git-rules.md`. NEVER type manual `git push --force` or `--force-with-lease`. The sanctioned release path is `push.ps1`.
4. **Architecture & Design**: See `docs/design.md`, `docs/requirements.md`, and `docs/constraints.md`.
