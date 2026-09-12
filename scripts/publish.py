"""Safely commit an exact local version-update scope and verify one GitHub push."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from urllib.parse import urlsplit

MAX_SCAN_BYTES = 8 * 1024 * 1024
NETWORK_TIMEOUT_SECONDS = 120
LOCK_NAME = "github-auto-publisher.lock"
RELEVANT_HOOKS = (
    "pre-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-push",
)

BLOCKED_EXACT_NAMES = {
    ".env",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "cookies",
    "cookies.json",
    "id_dsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
    "session.json",
    "subscription.json",
}
BLOCKED_SUFFIXES = {
    ".bak",
    ".backup",
    ".cache",
    ".db",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".swp",
    ".tmp",
}
BLOCKED_SEGMENTS = {
    ".aws",
    ".azure",
    ".git",
    ".kube",
    ".ssh",
    ".venv",
    "__pycache__",
    "backups",
    "browser-profile",
    "browser-profiles",
    "cache",
    "caches",
    "cookies",
    "logs",
    "node_modules",
    "sessions",
    "user-data-dir",
    "venv",
}

CONTENT_RULES = (
    (
        "private-key",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("github-token", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})")),
    ("openai-style-key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    (
        "jwt",
        re.compile(rb"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ),
)
SECRET_ASSIGNMENT = re.compile(
    rb"(?im)(?<![A-Za-z0-9])[\"']?(?:[A-Za-z0-9]+[_-])*"
    rb"(?:api[_-]?key|access[_-]?token|auth[_-]?token|authorization|client[_-]?secret|"
    rb"password|passwd|private[_-]?key|secret)[\"']?\s*[:=]\s*[\"']?([^\r\n\"';,#]{8,})"
)
SAFE_ASSIGNMENT_VALUE = re.compile(
    rb"(?ix)^(?:"
    rb"\$\{?[A-Z_][A-Z0-9_]*\}?|%[A-Z_][A-Z0-9_]*%|<[^>\r\n]+>|\*{3,}|x{3,}|"
    rb"changeme|dummy|example|none|null|placeholder|redacted|your_[A-Z0-9_-]+|"
    rb"(?:os\.getenv|os\.environ|getenv|settings\.|process\.env\.)[^\r\n]*"
    rb")$"
)
WINDOWS_USER_PATH = re.compile(
    rb"(?i)\b[A-Z]:(?:\\{1,2}|/)(?:Users|Documents and Settings)(?:\\{1,2}|/)"
    rb"[^\\/\r\n\"']+"
)
UNIX_USER_PATH = re.compile(rb"(?:/Users|/home)/[^/\s\"']+")
EMAIL_ADDRESS = re.compile(rb"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
SAFE_EMAIL_SUFFIXES = (b"@users.noreply.github.com", b"@example.com", b"@example.org")


@dataclass(frozen=True)
class Issue:
    code: str
    path: str | None = None
    detail: str | None = None

    def as_dict(self) -> dict[str, str]:
        result = {"code": self.code}
        if self.path is not None:
            result["path"] = self.path
        if self.detail is not None:
            result["detail"] = self.detail
        return result


class PublishError(Exception):
    def __init__(self, phase: str, issue: Issue) -> None:
        super().__init__(issue.code)
        self.phase = phase
        self.issue = issue


class LocalCommitError(PublishError):
    def __init__(self, phase: str, issue: Issue, commit: str) -> None:
        super().__init__(phase, issue)
        self.commit = commit


@dataclass(frozen=True)
class Settings:
    mode: str
    repo: Path
    remote: str
    branch: str
    message: str
    version_file: str
    includes: tuple[str, ...]
    checks: tuple[tuple[str, ...], ...]
    check_timeout: int
    allow_non_github_remote: bool


@dataclass(frozen=True)
class GitIdentity:
    name: str
    email: str


@dataclass(frozen=True)
class RemoteTarget:
    url: str
    host: str | None
    gh: str | None


@dataclass(frozen=True)
class Preflight:
    head: str
    remote_head: str
    target: RemoteTarget
    identity: GitIdentity
    config_fingerprint: str
    snapshot: tuple[tuple[str, str], ...]


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise PublishError("input", Issue("input.invalid"))


def execute(
    argv: Sequence[str],
    *,
    cwd: Path,
    input_text: str | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublishError("process", Issue("process.failed")) from exc


def execute_bytes(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            list(argv),
            cwd=cwd,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PublishError("process", Issue("process.failed")) from exc


def sanitized_git_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    environment = (source if source is not None else os.environ).copy()
    blocked_exact = {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_PARAMETERS",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_PREFIX",
        "GIT_REPLACE_REF_BASE",
        "GIT_WORK_TREE",
    }
    for key in tuple(environment):
        normalized = key.upper()
        if normalized in blocked_exact or normalized.startswith(
            ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")
        ):
            environment.pop(key, None)
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def git(
    repo: Path,
    *args: str,
    input_text: str | None = None,
    timeout: int | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return execute(
        ["git", "-C", str(repo), *args],
        cwd=repo,
        input_text=input_text,
        timeout=timeout,
        env=sanitized_git_environment(env),
    )


def require_git(repo: Path, phase: str, *args: str) -> str:
    result = git(repo, *args)
    if result.returncode != 0:
        raise PublishError(phase, Issue("git.command-failed"))
    return result.stdout.strip()


def nul_paths(value: str) -> set[str]:
    return {item.replace("\\", "/") for item in value.split("\0") if item}


def repository_root(raw_repo: str) -> Path:
    try:
        candidate = Path(raw_repo).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PublishError("input", Issue("repo.invalid")) from exc
    if not candidate.is_dir():
        raise PublishError("input", Issue("repo.invalid"))
    root = require_git(candidate, "input", "rev-parse", "--show-toplevel")
    try:
        return Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PublishError("input", Issue("repo.invalid")) from exc


def normalize_relative(repo: Path, raw: str) -> str:
    if not raw or "\0" in raw or any(char in raw for char in "*?[]"):
        raise PublishError("scope", Issue("scope.invalid-path"))
    supplied = Path(raw)
    if supplied.is_absolute():
        raise PublishError("scope", Issue("scope.absolute-path"))
    try:
        resolved = (repo / supplied).resolve(strict=False)
        relative = resolved.relative_to(repo)
    except (OSError, RuntimeError, ValueError) as exc:
        raise PublishError("scope", Issue("scope.outside-repository")) from exc
    if relative == Path(".") or (resolved.exists() and resolved.is_dir()):
        raise PublishError("scope", Issue("scope.file-required"))
    return relative.as_posix()


def parse_checks(values: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    parsed: list[tuple[str, ...]] = []
    for raw in values:
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PublishError("input", Issue("check.invalid-json")) from exc
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(part, str) or not part or "\0" in part for part in value)
        ):
            raise PublishError("input", Issue("check.invalid-argv"))
        parsed.append(tuple(value))
    return tuple(parsed)


def build_settings(namespace: argparse.Namespace) -> Settings:
    repo = repository_root(namespace.repo)
    includes = tuple(dict.fromkeys(normalize_relative(repo, raw) for raw in namespace.include))
    version_file = normalize_relative(repo, namespace.version_file)
    if version_file not in includes:
        raise PublishError("scope", Issue("version.not-in-scope", path=version_file))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", namespace.remote):
        raise PublishError("input", Issue("remote.invalid-name"))
    if namespace.branch.startswith("-"):
        raise PublishError("input", Issue("branch.invalid"))
    branch_check = git(repo, "check-ref-format", "--branch", namespace.branch)
    if branch_check.returncode != 0:
        raise PublishError("input", Issue("branch.invalid"))
    if any(char in namespace.message for char in "\r\n\0") or not namespace.message.strip():
        raise PublishError("input", Issue("message.invalid"))
    message_issues = scan_bytes("<commit-message>", namespace.message.encode("utf-8"))
    if message_issues:
        raise PublishError("privacy", message_issues[0])
    return Settings(
        mode=namespace.mode,
        repo=repo,
        remote=namespace.remote,
        branch=namespace.branch,
        message=namespace.message.strip(),
        version_file=version_file,
        includes=includes,
        checks=parse_checks(namespace.check_json),
        check_timeout=namespace.check_timeout,
        allow_non_github_remote=namespace.allow_non_github_remote,
    )


def git_directory(repo: Path) -> Path:
    raw = require_git(repo, "git-state", "rev-parse", "--absolute-git-dir")
    try:
        return Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PublishError("git-state", Issue("git.directory-invalid")) from exc


def ensure_no_release_hooks(repo: Path) -> None:
    for hook_name in RELEVANT_HOOKS:
        raw_path = require_git(repo, "git-state", "rev-parse", "--git-path", f"hooks/{hook_name}")
        hook_path = Path(raw_path)
        if not hook_path.is_absolute():
            hook_path = repo / hook_path
        if hook_path.is_file():
            raise PublishError("git-state", Issue("git.hook-present", detail=hook_name))


def ensure_repository_state(settings: Settings) -> tuple[str, Path, GitIdentity]:
    repo = settings.repo
    head = require_git(repo, "git-state", "rev-parse", "--verify", "HEAD")
    branch_result = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch_result.returncode != 0:
        raise PublishError("git-state", Issue("git.detached-head"))
    if branch_result.stdout.strip() != settings.branch:
        raise PublishError("git-state", Issue("git.branch-mismatch"))

    index = git(repo, "diff", "--cached", "--quiet", "--exit-code")
    if index.returncode == 1:
        raise PublishError("git-state", Issue("git.index-dirty"))
    if index.returncode != 0:
        raise PublishError("git-state", Issue("git.index-check-failed"))

    git_dir = git_directory(repo)
    in_progress = (
        "MERGE_HEAD",
        "CHERRY_PICK_HEAD",
        "REVERT_HEAD",
        "BISECT_LOG",
        "rebase-apply",
        "rebase-merge",
        "sequencer",
    )
    if any((git_dir / marker).exists() for marker in in_progress):
        raise PublishError("git-state", Issue("git.operation-in-progress"))
    ensure_no_release_hooks(repo)

    name = git(repo, "config", "--local", "--get", "user.name")
    email = git(repo, "config", "--local", "--get", "user.email")
    identity_name = name.stdout.strip()
    identity_email = email.stdout.strip()
    if name.returncode != 0 or not identity_name or email.returncode != 0:
        raise PublishError("git-state", Issue("git.identity-missing"))
    suffix = "@users.noreply.github.com"
    if not identity_email.lower().endswith(suffix):
        raise PublishError("privacy", Issue("git.identity-not-noreply"))
    local_part = identity_email[: -len(suffix)]
    github_handle = local_part.split("+", 1)[-1]
    if not github_handle or identity_name.casefold() != github_handle.casefold():
        raise PublishError("privacy", Issue("git.identity-name-not-handle"))
    return head, git_dir, GitIdentity(name=identity_name, email=identity_email)


def configured_remote_urls(settings: Settings, *, push: bool) -> tuple[str, ...]:
    option = ["--push"] if push else []
    result = git(settings.repo, "remote", "get-url", *option, "--all", settings.remote)
    urls = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if result.returncode != 0 or not urls:
        raise PublishError("remote", Issue("remote.missing"))
    return urls


def raw_remote_urls(settings: Settings, *, push: bool) -> tuple[str, ...]:
    suffix = "pushurl" if push else "url"
    result = git(settings.repo, "config", "--get-all", f"remote.{settings.remote}.{suffix}")
    if result.returncode == 1:
        return ()
    urls = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if result.returncode != 0 or not urls:
        raise PublishError("remote", Issue("remote.config-invalid"))
    return urls


def has_remote_credentials(url: str) -> bool:
    if "://" not in url:
        return False
    parsed = urlsplit(url)
    if parsed.scheme.lower() in {"http", "https"}:
        return parsed.username is not None or parsed.password is not None
    return parsed.password is not None


def github_host(url: str) -> str | None:
    if "://" in url:
        return urlsplit(url).hostname
    match = re.match(r"^(?:[^@/:]+@)?([^/:]+):", url)
    return match.group(1) if match else None


def find_gh() -> str | None:
    located = shutil.which("gh")
    if located:
        return located
    if os.name == "nt":
        roots = [os.environ.get("ProgramFiles"), os.environ.get("LOCALAPPDATA")]
        candidates = []
        if roots[0]:
            candidates.append(Path(roots[0]) / "GitHub CLI" / "gh.exe")
        if roots[1]:
            candidates.extend(
                [
                    Path(roots[1]) / "Programs" / "GitHub CLI" / "gh.exe",
                    Path(roots[1]) / "Microsoft" / "WinGet" / "Links" / "gh.exe",
                ]
            )
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    return None


def transport_environment(target: RemoteTarget) -> dict[str, str]:
    environment = sanitized_git_environment()
    for variable in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
    ):
        environment.pop(variable, None)
    if target.gh is not None:
        gh_directory = str(Path(target.gh).parent)
        environment["PATH"] = gh_directory + os.pathsep + environment.get("PATH", "")
    return environment


def transport_git(
    settings: Settings,
    target: RemoteTarget,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    command = [
        "git",
        "-c",
        "push.followTags=false",
        "-c",
        "push.gpgSign=false",
        "-c",
        "http.extraHeader=",
    ]
    if target.gh is not None and target.host is not None:
        command.extend(
            [
                "-c",
                "credential.helper=",
                "-c",
                f"credential.https://{target.host}.helper=!gh auth git-credential",
                "-c",
                f"http.https://{target.host}/.extraHeader=",
            ]
        )
    command.extend(["-C", str(settings.repo), *args])
    return execute(
        command,
        cwd=settings.repo,
        timeout=NETWORK_TIMEOUT_SECONDS,
        env=transport_environment(target),
    )


def ensure_remote_and_auth(settings: Settings) -> tuple[RemoteTarget, str]:
    raw_fetch_urls = raw_remote_urls(settings, push=False)
    raw_push_urls = raw_remote_urls(settings, push=True)
    if len(raw_fetch_urls) != 1:
        issue = "remote.missing" if not raw_fetch_urls else "remote.multiple-url"
        raise PublishError("remote", Issue(issue))
    if len(raw_push_urls) > 1:
        raise PublishError("remote", Issue("remote.multiple-pushurl"))
    if not raw_push_urls:
        raw_push_urls = raw_fetch_urls

    fetch_urls = configured_remote_urls(settings, push=False)
    push_urls = configured_remote_urls(settings, push=True)
    for url in (*fetch_urls, *push_urls):
        if has_remote_credentials(url):
            raise PublishError("remote", Issue("remote.credentials"))
    if len(fetch_urls) != 1:
        raise PublishError("remote", Issue("remote.multiple-url"))
    if len(push_urls) != 1:
        raise PublishError("remote", Issue("remote.multiple-pushurl"))
    if fetch_urls[0] != push_urls[0]:
        raise PublishError("remote", Issue("remote.push-url-mismatch"))
    if raw_fetch_urls != fetch_urls or raw_push_urls != push_urls:
        raise PublishError("remote", Issue("remote.url-rewrite"))

    url = fetch_urls[0]
    host = github_host(url)
    is_github = host is not None and host.lower() == "github.com"
    if not is_github and not settings.allow_non_github_remote:
        raise PublishError("remote", Issue("remote.not-github"))
    gh: str | None = None
    if is_github:
        assert host is not None
        if urlsplit(url).scheme.lower() != "https":
            raise PublishError("remote", Issue("remote.https-required"))
        gh = find_gh()
        if gh is None:
            raise PublishError("github-cli", Issue("gh.unavailable"))
        auth = execute(
            [gh, "auth", "status", "--hostname", host],
            cwd=settings.repo,
            timeout=30,
            env=transport_environment(RemoteTarget(url=url, host=host, gh=gh)),
        )
        if auth.returncode != 0:
            raise PublishError("github-cli", Issue("gh.not-authenticated"))

    target = RemoteTarget(url=url, host=host, gh=gh)
    remote_head = remote_branch_sha(settings, target)
    if remote_head is None:
        raise PublishError("remote", Issue("remote.branch-missing"))
    return target, remote_head


def remote_branch_sha(settings: Settings, target: RemoteTarget) -> str | None:
    ref = f"refs/heads/{settings.branch}"
    result = transport_git(settings, target, "ls-remote", "--heads", settings.remote, ref)
    if result.returncode != 0:
        raise PublishError("remote", Issue("remote.read-failed"))
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None
    fields = lines[0].split()
    if len(fields) != 2 or fields[1] != ref or not re.fullmatch(r"[0-9a-fA-F]{40,64}", fields[0]):
        raise PublishError("remote", Issue("remote.read-invalid"))
    return fields[0].lower()


def ensure_remote_matches_head(settings: Settings, head: str, remote_head: str) -> None:
    if remote_head == head.lower():
        return
    result = git(settings.repo, "merge-base", "--is-ancestor", remote_head, head)
    if result.returncode == 0:
        raise PublishError("remote", Issue("remote.local-ahead"))
    raise PublishError("remote", Issue("remote.not-ancestor"))


def config_fingerprint(repo: Path) -> str:
    result = execute_bytes(
        ["git", "-C", str(repo), "config", "--null", "--list", "--show-origin"],
        cwd=repo,
        env=sanitized_git_environment(),
    )
    if result.returncode != 0:
        raise PublishError("git-state", Issue("git.config-read-failed"))
    return hashlib.sha256(result.stdout).hexdigest()


def changed_paths(repo: Path) -> set[str]:
    tracked = git(repo, "diff", "--name-only", "-z", "--no-renames", "HEAD", "--")
    untracked = git(repo, "ls-files", "--others", "--exclude-standard", "-z", "--")
    if tracked.returncode != 0 or untracked.returncode != 0:
        raise PublishError("scope", Issue("scope.enumeration-failed"))
    return nul_paths(tracked.stdout) | nul_paths(untracked.stdout)


def blocked_path(relative: str) -> bool:
    parts = tuple(part.lower() for part in Path(relative).parts)
    name = parts[-1]
    if name == ".env" or name.startswith(".env."):
        return True
    if name in BLOCKED_EXACT_NAMES or any(name.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        return True
    return any(part in BLOCKED_SEGMENTS for part in parts)


def scan_bytes(relative: str, content: bytes) -> list[Issue]:
    issues: list[Issue] = []
    if WINDOWS_USER_PATH.search(content) or UNIX_USER_PATH.search(content):
        issues.append(Issue("privacy.local-path", path=relative))
    for rule, pattern in CONTENT_RULES:
        if pattern.search(content):
            issues.append(Issue("privacy.secret", path=relative, detail=rule))
    for match in SECRET_ASSIGNMENT.finditer(content):
        value = match.group(1).strip().lower()
        if SAFE_ASSIGNMENT_VALUE.fullmatch(value) is None:
            issues.append(Issue("privacy.secret", path=relative, detail="sensitive-assignment"))
            break
    for match in EMAIL_ADDRESS.finditer(content):
        address = match.group(0).lower()
        if not address.endswith(SAFE_EMAIL_SUFFIXES):
            issues.append(Issue("privacy.email", path=relative))
            break
    return issues


def scan_candidate_paths(settings: Settings) -> None:
    for relative in settings.includes:
        if blocked_path(relative):
            raise PublishError("privacy", Issue("privacy.path", path=relative))
        path = settings.repo / relative
        if path.is_symlink():
            raise PublishError("privacy", Issue("privacy.symlink", path=relative))
        if not path.exists():
            continue
        try:
            size = path.stat().st_size
            if size > MAX_SCAN_BYTES:
                raise PublishError("privacy", Issue("privacy.file-too-large", path=relative))
            content = path.read_bytes()
        except OSError as exc:
            raise PublishError("privacy", Issue("privacy.read-failed", path=relative)) from exc
        issues = scan_bytes(relative, content)
        if issues:
            raise PublishError("privacy", issues[0])


def hash_path(repo: Path, relative: str) -> str:
    path = repo / relative
    if not path.exists():
        return "missing"
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise PublishError("snapshot", Issue("snapshot.read-failed", path=relative)) from exc
    return digest.hexdigest()


def snapshot(repo: Path, includes: Sequence[str]) -> tuple[tuple[str, str], ...]:
    return tuple((relative, hash_path(repo, relative)) for relative in includes)


def run_checks(settings: Settings, before: tuple[tuple[str, str], ...]) -> None:
    for index, command in enumerate(settings.checks, start=1):
        try:
            result = subprocess.run(
                list(command),
                cwd=settings.repo,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
                timeout=settings.check_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PublishError(
                "validation",
                Issue("validation.execution-failed", detail=f"check-{index}"),
            ) from exc
        if result.returncode != 0:
            raise PublishError(
                "validation",
                Issue("validation.failed", detail=f"check-{index}"),
            )
    if snapshot(settings.repo, settings.includes) != before:
        raise PublishError("validation", Issue("validation.changed"))


def perform_preflight(settings: Settings, *, lock_path: Path) -> Preflight:
    head, _, identity = ensure_repository_state(settings)
    if lock_path.exists() and settings.mode == "plan":
        raise PublishError("lock", Issue("publish.locked"))
    target, remote_head = ensure_remote_and_auth(settings)
    ensure_remote_matches_head(settings, head, remote_head)
    current_changes = changed_paths(settings.repo)
    missing = [relative for relative in settings.includes if relative not in current_changes]
    if missing:
        raise PublishError("scope", Issue("scope.include-not-changed", path=missing[0]))
    if settings.version_file not in current_changes:
        raise PublishError("scope", Issue("version.not-changed", path=settings.version_file))
    scan_candidate_paths(settings)
    before = snapshot(settings.repo, settings.includes)
    run_checks(settings, before)
    head_after, _, identity_after = ensure_repository_state(settings)
    if head_after.lower() != head.lower() or identity_after != identity:
        raise PublishError("validation", Issue("validation.repository-changed"))
    target_after, remote_after = ensure_remote_and_auth(settings)
    if target_after != target or remote_after != remote_head:
        raise PublishError("validation", Issue("validation.remote-changed"))
    return Preflight(
        head=head.lower(),
        remote_head=remote_head,
        target=target,
        identity=identity,
        config_fingerprint=config_fingerprint(settings.repo),
        snapshot=before,
    )


def ensure_ready_to_push(settings: Settings, state: Preflight, commit: str) -> None:
    current_head, _, identity = ensure_repository_state(settings)
    if current_head.lower() != commit:
        raise PublishError("push", Issue("push.head-changed"))
    if identity != state.identity:
        raise PublishError("push", Issue("push.identity-changed"))
    if config_fingerprint(settings.repo) != state.config_fingerprint:
        raise PublishError("push", Issue("push.config-changed"))
    target, remote_head = ensure_remote_and_auth(settings)
    if target != state.target or remote_head != state.remote_head:
        raise PublishError("push", Issue("push.remote-changed"))
    scan_git_objects(settings, commit)


@contextmanager
def publish_lock(lock_path: Path) -> Iterator[None]:
    try:
        descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise PublishError("lock", Issue("publish.locked")) from exc
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.close(descriptor)
        descriptor = -1
        yield
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def staged_paths(repo: Path) -> set[str]:
    result = git(repo, "diff", "--cached", "--name-only", "-z", "--no-renames")
    if result.returncode != 0:
        raise PublishError("stage", Issue("stage.enumeration-failed"))
    return nul_paths(result.stdout)


def unstage_exact(settings: Settings) -> None:
    result = git(
        settings.repo,
        "restore",
        "--staged",
        "--source=HEAD",
        "--",
        *settings.includes,
    )
    if result.returncode != 0:
        raise PublishError("stage", Issue("stage.rollback-failed"))


def git_object_bytes(
    repo: Path,
    object_spec: str,
    *,
    phase: str,
    relative: str,
) -> bytes | None:
    resolved = git(repo, "rev-parse", "--verify", "--quiet", object_spec)
    if resolved.returncode == 1:
        return None
    object_id = resolved.stdout.strip()
    if resolved.returncode != 0 or re.fullmatch(r"[0-9a-fA-F]{40,64}", object_id) is None:
        raise PublishError(phase, Issue("privacy.object-invalid", path=relative))
    size_result = git(repo, "cat-file", "-s", object_id)
    try:
        size = int(size_result.stdout.strip())
    except ValueError as exc:
        raise PublishError(phase, Issue("privacy.object-invalid", path=relative)) from exc
    if size_result.returncode != 0 or size < 0:
        raise PublishError(phase, Issue("privacy.object-invalid", path=relative))
    if size > MAX_SCAN_BYTES:
        raise PublishError(phase, Issue("privacy.file-too-large", path=relative))
    content = execute_bytes(
        ["git", "-C", str(repo), "cat-file", "blob", object_id],
        cwd=repo,
        env=sanitized_git_environment(),
    )
    if content.returncode != 0 or len(content.stdout) != size:
        raise PublishError(phase, Issue("privacy.object-read-failed", path=relative))
    return content.stdout


def scan_git_objects(settings: Settings, commit: str | None) -> None:
    for relative in settings.includes:
        if blocked_path(relative):
            raise PublishError("privacy", Issue("privacy.path", path=relative))
        object_spec = f":{relative}" if commit is None else f"{commit}:{relative}"
        content = git_object_bytes(
            settings.repo,
            object_spec,
            phase="privacy",
            relative=relative,
        )
        if content is None:
            continue
        issues = scan_bytes(relative, content)
        if issues:
            raise PublishError("privacy", issues[0])


def stage_exact(settings: Settings, expected_snapshot: tuple[tuple[str, str], ...]) -> None:
    result = git(settings.repo, "add", "--", *settings.includes)
    if result.returncode != 0:
        unstage_exact(settings)
        raise PublishError("stage", Issue("stage.failed"))
    try:
        if snapshot(settings.repo, settings.includes) != expected_snapshot:
            raise PublishError("stage", Issue("stage.concurrent-change"))
        actual = staged_paths(settings.repo)
        if actual != set(settings.includes):
            raise PublishError("stage", Issue("stage.scope-mismatch"))
        scan_git_objects(settings, None)
    except PublishError:
        unstage_exact(settings)
        raise


def commit_environment(identity: GitIdentity) -> dict[str, str]:
    environment = sanitized_git_environment()
    for key in tuple(environment):
        normalized = key.upper()
        if normalized == "EMAIL" or normalized.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_")):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_AUTHOR_NAME": identity.name,
            "GIT_AUTHOR_EMAIL": identity.email,
            "GIT_COMMITTER_NAME": identity.name,
            "GIT_COMMITTER_EMAIL": identity.email,
        }
    )
    return environment


def verify_commit_metadata(
    settings: Settings,
    commit: str,
    previous_head: str,
    identity: GitIdentity,
) -> None:
    parents = require_git(settings.repo, "commit", "rev-list", "--parents", "-n", "1", commit).split()
    if parents != [commit, previous_head]:
        raise PublishError("commit", Issue("commit.parent-mismatch"))
    metadata = require_git(
        settings.repo,
        "commit",
        "show",
        "-s",
        "--format=%an%x00%ae%x00%cn%x00%ce%x00%B",
        commit,
    ).split("\0", 4)
    expected = [identity.name, identity.email, identity.name, identity.email]
    if len(metadata) != 5 or metadata[:4] != expected:
        raise PublishError("privacy", Issue("commit.identity-mismatch"))
    if metadata[4].rstrip("\n") != settings.message:
        raise PublishError("commit", Issue("commit.message-mismatch"))


def commit_exact(settings: Settings, previous_head: str, identity: GitIdentity) -> str:
    result = git(
        settings.repo,
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-m",
        settings.message,
        "--",
        *settings.includes,
        env=commit_environment(identity),
    )
    current = require_git(settings.repo, "commit", "rev-parse", "HEAD").lower()
    if result.returncode != 0:
        if current == previous_head:
            unstage_exact(settings)
            raise PublishError("commit", Issue("commit.failed"))
        raise LocalCommitError("commit", Issue("commit.result-uncertain"), current)
    try:
        committed = git(
            settings.repo,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-z",
            "-r",
            "--no-renames",
            current,
        )
        if committed.returncode != 0 or nul_paths(committed.stdout) != set(settings.includes):
            raise PublishError("commit", Issue("commit.scope-mismatch"))
        if staged_paths(settings.repo):
            raise PublishError("commit", Issue("commit.index-not-clean"))
        scan_git_objects(settings, current)
        verify_commit_metadata(settings, current, previous_head, identity)
    except PublishError as exc:
        raise LocalCommitError(exc.phase, exc.issue, current) from exc
    return current


def push_once(settings: Settings, target: RemoteTarget) -> subprocess.CompletedProcess[str]:
    refspec = f"HEAD:refs/heads/{settings.branch}"
    return transport_git(
        settings,
        target,
        "push",
        "--porcelain",
        settings.remote,
        refspec,
    )


def output(
    status: str,
    phase: str,
    message: str,
    *,
    issues: Sequence[Issue] = (),
    commit: str | None = None,
    paths: Sequence[str] = (),
) -> None:
    payload: dict[str, object] = {
        "status": status,
        "phase": phase,
        "message": message,
    }
    if issues:
        payload["issues"] = [issue.as_dict() for issue in issues]
    if commit is not None:
        payload["commit"] = commit
    if paths:
        payload["paths"] = list(paths)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = SafeArgumentParser(description=__doc__)
    result.add_argument("mode", choices=("plan", "publish"))
    result.add_argument("--repo", required=True)
    result.add_argument("--remote", required=True)
    result.add_argument("--branch", required=True)
    result.add_argument("--message", required=True)
    result.add_argument("--version-file", required=True)
    result.add_argument("--include", action="append", required=True)
    result.add_argument("--check-json", action="append", required=True)
    result.add_argument("--check-timeout", type=int, default=900)
    result.add_argument("--allow-non-github-remote", action="store_true")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    commit: str | None = None
    push_attempted = False
    try:
        namespace = parser().parse_args(argv)
        if namespace.check_timeout < 1 or namespace.check_timeout > 3600:
            raise PublishError("input", Issue("check.invalid-timeout"))
        settings = build_settings(namespace)
        git_dir = git_directory(settings.repo)
        lock_path = git_dir / LOCK_NAME

        if settings.mode == "plan":
            state = perform_preflight(settings, lock_path=lock_path)
            output(
                "ready",
                "plan",
                "Preflight and validation passed; the publisher did not stage, commit, or push.",
                commit=state.head,
                paths=settings.includes,
            )
            return 0

        with publish_lock(lock_path):
            state = perform_preflight(settings, lock_path=lock_path)
            stage_exact(settings, state.snapshot)
            commit = commit_exact(settings, state.head, state.identity)
            ensure_ready_to_push(settings, state, commit)
            push_attempted = True
            push_error: PublishError | None = None
            try:
                push = push_once(settings, state.target)
            except PublishError as exc:
                push = None
                push_error = exc
            try:
                if config_fingerprint(settings.repo) != state.config_fingerprint:
                    raise PublishError("remote-readback", Issue("remote.config-changed"))
                target_after, remote_after = ensure_remote_and_auth(settings)
                if target_after != state.target:
                    raise PublishError("remote-readback", Issue("remote.target-changed"))
            except PublishError as exc:
                output(
                    "unconfirmed",
                    exc.phase,
                    "The local commit exists, but remote state could not be confirmed; no retry was attempted.",
                    issues=(exc.issue,),
                    commit=commit,
                )
                return 3
            if remote_after == commit:
                output(
                    "pushed",
                    "remote-readback",
                    "Remote branch matches the local commit.",
                    commit=commit,
                    paths=settings.includes,
                )
                return 0
            if push is not None and push.returncode == 0:
                output(
                    "unconfirmed",
                    "remote-readback",
                    "Push returned success but the remote branch did not match; no retry was attempted.",
                    issues=(Issue("remote.unconfirmed"),),
                    commit=commit,
                )
            else:
                issue = push_error.issue if push_error is not None else Issue("push.failed")
                output(
                    "local_commit_only",
                    "push",
                    "The local commit exists but the single push was not confirmed; no retry was attempted.",
                    issues=(issue,),
                    commit=commit,
                )
            return 3
    except PublishError as exc:
        if isinstance(exc, LocalCommitError):
            commit = exc.commit
        if commit is not None:
            status = "unconfirmed" if push_attempted else "local_commit_only"
            output(
                status,
                exc.phase,
                "The local commit exists, but no remote update was confirmed; no retry was attempted.",
                issues=(exc.issue,),
                commit=commit,
            )
            return 3
        output(
            "blocked",
            exc.phase,
            "Publication stopped before a confirmed remote update.",
            issues=(exc.issue,),
        )
        return 2
    except Exception:  # noqa: BLE001 - the CLI boundary must not leak raw local data.
        if commit is not None:
            status = "unconfirmed" if push_attempted else "local_commit_only"
            output(
                status,
                "internal",
                "The local commit exists, but publication ended unexpectedly; no retry was attempted.",
                issues=(Issue("internal.error"),),
                commit=commit,
            )
            return 4
        output(
            "blocked",
            "internal",
            "Publication stopped because of an unexpected internal error.",
            issues=(Issue("internal.error"),),
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
