---
name: github-auto-publisher
description: Use when a GitHub-hosted project has a completed local version update that should be committed and pushed, especially when exact change ownership, secret/privacy scanning, non-force publication, GitHub CLI authentication, or remote commit confirmation are required.
---

# GitHub Auto Publisher

Turn one authorized, completed version update into one exact commit, one ordinary push, and a verified remote SHA. Do not treat arbitrary file saves as completion and do not install a permanent watcher or Git hook.

## Resolve the release contract

Before publishing, identify:

- the repository root, current named branch, and existing GitHub remote;
- every task-owned changed file as an exact repository-relative path;
- the changed version file and commit message;
- fresh validation commands expressed as argument arrays, not shell strings.

If the current request or a standing user preference already authorizes publishing this repository, continue without asking again. Otherwise run `plan` only and obtain authorization immediately before `publish`.

Require `gh auth status --hostname github.com` to succeed using the saved CLI login. If authentication is absent, stop and let the user complete `gh auth login`; never capture, print, copy, or store login codes, Tokens, or session state. The publisher ignores environment-supplied GitHub Token variables and injects `gh auth git-credential` only into its own Git processes. Do not run `gh auth setup-git`, because that changes persistent Git configuration.

Treat every validation command as trusted executable code selected for this release. The publisher runs commands without a shell, then rechecks the named branch, `HEAD`, index, identity, hooks, remote target, and remote SHA. A change to any of those protected states blocks publication.

## Plan, then publish

Locate `scripts/publish.py` relative to this Skill. On Windows PowerShell, build one reusable argument array:

```powershell
$publisher = Join-Path $env:USERPROFILE '.agents\skills\github-auto-publisher\scripts\publish.py'
$checks = @(
  (ConvertTo-Json @('python', '-m', 'unittest', 'discover', '-s', 'tests', '-v') -Compress)
)
$releaseArgs = @(
  '--repo', (Get-Location).Path,
  '--remote', 'origin',
  '--branch', 'main',
  '--message', 'release: v1.2.0',
  '--version-file', 'VERSION',
  '--include', 'VERSION',
  '--include', 'src/publisher.py',
  '--include', 'tests/test_publisher.py',
  '--check-json', $checks[0]
)

python $publisher plan @releaseArgs
python $publisher publish @releaseArgs
```

Run `publish` only after `plan` returns `status: ready` and the exact path list is correct. The script repeats all checks under a single-publisher lock before mutation.

## Privacy is a blocking gate

Treat all of the following as private and stop before commit:

- API keys, GitHub PATs, access/auth Tokens, OAuth/client secrets, passwords, JWTs, SSH/private keys, and credential-bearing remote URLs;
- `.env`, credential/secret files, cookies, sessions, browser profiles, subscriptions, caches, logs, databases, backups, and temporary files;
- absolute local user paths, personal email addresses, and other machine-specific identifiers.

Report only the repository-relative file and rule code. Never echo the matched value. Use Gitleaks as optional defense in depth when already installed; the bundled scanner remains mandatory.

## Preserve Git state

- Require a clean index; preserve unrelated tracked and untracked working-tree changes.
- Stage only repeated `--include` paths. Never use `git add -A`, broad globs, or a workspace root as a pathspec.
- Scan the working files, the exact staged Git objects, and the final commit objects. A clean/smudge filter must never bypass the privacy gate.
- Require a changed `--version-file` inside the exact include set.
- Require exactly one raw fetch URL and at most one raw push URL, with the same resolved target. Reject URL rewrite rules affecting the target. For GitHub publication, require credential-free HTTPS.
- Require the existing remote branch SHA to equal local `HEAD` before the release commit. Do not carry older local-only commits into this release.
- Refuse detached HEAD, merge/rebase/cherry-pick/revert/bisect state, branch mismatch, remote drift, a relevant commit/push hook, or another publisher's lock.
- Require repository-local Git identity whose name is the GitHub handle from its noreply email. Override author/committer environment variables with that verified identity and verify the final commit identity, message, exact parent, and file scope.
- Recheck `HEAD`, index, Git configuration, target URL, and remote baseline immediately before the single push. Recheck the target and remote SHA after it.
- Disable implicit commit/push signing and inherited HTTP authorization headers for this operation; authentication must come from the verified CLI helper.
- Never pull, rebase, reset, delete refs, mirror, force-push, rewrite history, or retry a push automatically.

## Interpret the result

| Status | Meaning | Next action |
|---|---|---|
| `ready` | Plan and validation passed; no commit or push occurred | Review paths, then run `publish` |
| `pushed` | Remote branch SHA equals local `HEAD` | Report the commit and checks |
| `blocked` | No confirmed remote update | Fix the named gate; do not bypass it |
| `local_commit_only` | Commit exists locally, push was not confirmed | Inspect remote state; never blindly retry |
| `unconfirmed` | Push returned success but SHA readback disagreed | Treat as uncertain and investigate |

The script submits at most one `git push --porcelain` operation to the already-verified URL, overrides `push.followTags=false`, and confirms the same URL with `git ls-remote`. A command exit code or GitHub acceptance alone is not completion.

## Common mistakes

- Do not let multiple Agents commit or push independently; only the release owner invokes this Skill.
- Do not include generated files merely because they changed; include them only when the verified release requires them.
- Do not use `--allow-non-github-remote` for a GitHub release; that flag exists for isolated local-remote tests.
- Do not turn `blocked` into an automatic override. Narrow the scope or correct the repository state.

## References

- Git hooks: https://git-scm.com/docs/githooks
- Git push behavior: https://git-scm.com/docs/git-push
- Git credential helpers: https://git-scm.com/docs/gitcredentials
- GitHub CLI Git setup: https://cli.github.com/manual/gh_auth_setup-git
- Optional Gitleaks defense in depth: https://github.com/gitleaks/gitleaks
