# GitHub Auto Publisher

A Codex Skill for publishing a completed local version update as one exact commit and one verified GitHub push.

The release gate checks exact file ownership, a changed version file, repository-local noreply identity, privacy-sensitive paths and content, staged and committed Git objects, validation side effects, URL rewrites, remote drift, push destinations, hooks, and final remote SHA.

## Install

Copy this repository to the shared Agent skills directory under the folder name `github-auto-publisher`. No credentials, browser profile, or login state belong in the Skill directory.

## Use

Ask the Agent to publish a completed, verified project version with `$github-auto-publisher`. The Agent resolves the exact included paths and validation commands, runs `plan`, reviews the structured result, and then runs `publish` when publication is already authorized.

GitHub authentication is provided by an existing GitHub CLI login. The publisher uses the CLI credential helper only for its own HTTPS Git processes and never reads or stores the credential value.

See [SKILL.md](SKILL.md) for the complete workflow and safety contract.
