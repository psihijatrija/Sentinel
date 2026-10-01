---
inclusion: auto
---

# Git Rules for Sentinel Repository

## The sanctioned push/release path: `D:\Gorstak\push.ps1`

**`push.ps1` is the owner-authorized tool for pushing code and publishing releases.** Prefer it
over hand-rolled git commands for the end-of-work release sequence. It is safe to run without
pausing for confirmation, including when the repo does not yet exist locally.

What it does (this is standing, pre-authorized policy - do NOT re-prompt for it):

- Initialises a git repo if `.git` is missing (a deleted/absent `.git` is NOT a blocker - the
  script recreates it and re-links `origin`).
- Commits local changes, creates the GitHub repo if absent, then fetches + rebases onto
  `origin/main`.
- Resolves divergence automatically: local-ahead -> push; remote-ahead -> reset to remote;
  **both diverged -> `force-with-lease`, local wins.**
- Uploads each `releases\<SEMVER>\` folder as a GitHub release with its assets.

Typical invocation for this project: `.\push.ps1 -ProjectFilter sentinel` (run from `D:\Gorstak`).

Because the owner has encoded these decisions in the script, running `push.ps1` (or asking the
owner to) is the correct way to complete a release. Do not treat its internal force-with-lease as
a rule violation - that prohibition (below) is about *ad-hoc, manual* force pushes.

## NEVER force push MANUALLY (outside `push.ps1`)

**Ad-hoc `git push --force` / `git push --force-with-lease` typed by hand are FORBIDDEN on this
repository.**

This rule exists because a previous *manual* force push destroyed 183 commits of project history.
The history was recovered, but this must never happen again. The `push.ps1` path is exempt: it
fetches and rebases first, uses `--force-with-lease` (not bare `--force`), and encodes the owner's
"local wins on divergence" policy.

### What to do instead (for manual git work):
- If a push is rejected, investigate why - do NOT force it through by hand; prefer `push.ps1`
- If commits need to be reverted, use `git revert` (creates new commits, preserves history)
- If a branch is behind remote, use `git pull --rebase` or `git merge`
- If you accidentally committed large files that GitHub rejects, remove them with a new commit (not by rewriting history)

### Also forbidden:
- `git reset --hard` on commits that have been pushed
- `git rebase` on commits that have been pushed to remote
- Any history-rewriting operation on shared branches

### Allowed:
- `git reset --soft` or `git reset` (unstaging) on LOCAL unpushed work
- `git rebase` on LOCAL unpushed commits before first push
- `git commit --amend` ONLY on unpushed commits
