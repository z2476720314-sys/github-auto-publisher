from __future__ import annotations

import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
PUBLISH = SKILL_ROOT / "scripts" / "publish.py"


def run_process(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


def run_git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = run_process(["git", "-C", str(repo), *args])
    if check and result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result


class PublisherTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.remote = self.root / "remote.git"
        self.repo = self.root / "work"
        self.repo.mkdir()

        run_process(["git", "init", "--bare", str(self.remote)])
        run_git(self.repo, "init", "--initial-branch=main")
        run_git(self.repo, "config", "user.name", "publisher")
        run_git(self.repo, "config", "user.email", "publisher@users.noreply.github.com")
        self.write("VERSION", "1.0.0\n")
        self.write("app.txt", "stable\n")
        run_git(self.repo, "add", "--", "VERSION", "app.txt")
        run_git(self.repo, "commit", "-m", "initial")
        run_git(self.repo, "remote", "add", "origin", str(self.remote))
        run_git(self.repo, "push", "-u", "origin", "main")
        self.initial_head = run_git(self.repo, "rev-parse", "HEAD").stdout.strip()

        self.write("VERSION", "1.1.0\n")
        self.write("app.txt", "released\n")
        self.write("unrelated.txt", "keep local\n")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
        return path

    def invoke(
        self,
        mode: str,
        *,
        includes: list[str] | None = None,
        checks: list[list[str]] | None = None,
        allow_local: bool = True,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any]]:
        args = self.publisher_args(
            mode,
            includes=includes,
            checks=checks,
            allow_local=allow_local,
        )
        result = run_process(args, cwd=self.repo)
        payload = json.loads(result.stdout)
        return result, payload

    def publisher_args(
        self,
        mode: str,
        *,
        includes: list[str] | None = None,
        checks: list[list[str]] | None = None,
        allow_local: bool = True,
    ) -> list[str]:
        included = includes if includes is not None else ["VERSION", "app.txt"]
        commands = checks if checks is not None else [
            [
                sys.executable,
                "-c",
                "from pathlib import Path; assert Path('VERSION').read_text().strip() == '1.1.0'",
            ]
        ]
        args = [
            sys.executable,
            str(PUBLISH),
            mode,
            "--repo",
            str(self.repo),
            "--remote",
            "origin",
            "--branch",
            "main",
            "--message",
            "release: v1.1.0",
            "--version-file",
            "VERSION",
        ]
        for relative in included:
            args.extend(["--include", relative])
        for command in commands:
            args.extend(["--check-json", json.dumps(command)])
        if allow_local:
            args.append("--allow-non-github-remote")
        return args

    @staticmethod
    def issue_codes(payload: dict[str, Any]) -> set[str]:
        return {str(issue["code"]) for issue in payload.get("issues", [])}

    def remote_head(self) -> str:
        return run_git(self.remote, "rev-parse", "refs/heads/main").stdout.strip()

    def git_dir(self) -> Path:
        git_dir = Path(run_git(self.repo, "rev-parse", "--git-dir").stdout.strip())
        return git_dir if git_dir.is_absolute() else self.repo / git_dir

    def test_plan_is_read_only_and_reports_ready(self) -> None:
        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)
        self.assertEqual(run_git(self.repo, "diff", "--quiet", check=False).returncode, 1)

    def test_publish_commits_exact_scope_and_preserves_unrelated_changes(self) -> None:
        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "pushed")
        local_head = run_git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(self.remote_head(), local_head)
        committed = run_git(
            self.repo,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "--no-renames",
            "HEAD",
        ).stdout.splitlines()
        self.assertEqual(set(committed), {"VERSION", "app.txt"})
        self.assertTrue((self.repo / "unrelated.txt").exists())
        self.assertIn("?? unrelated.txt", run_git(self.repo, "status", "--short").stdout)

    def test_blocked_path_never_reaches_a_commit(self) -> None:
        private_assignment = "SERVICE_" + "API_" + "KEY=" + "do-not-print-this-value\n"
        self.write(".env", private_assignment)

        result, payload = self.invoke("publish", includes=["VERSION", "app.txt", ".env"])

        self.assertEqual(result.returncode, 2)
        self.assertEqual(payload["status"], "blocked")
        self.assertIn("privacy.path", self.issue_codes(payload))
        self.assertNotIn("do-not-print-this-value", result.stdout + result.stderr)
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)

    def test_secret_content_is_blocked_without_echoing_the_value(self) -> None:
        sensitive_value = "super-" + "secret-" + "api-value-123456"
        assignment = "api_" + "key=" + sensitive_value + "\n"
        self.write("app.txt", assignment)

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.secret", self.issue_codes(payload))
        self.assertNotIn(sensitive_value, result.stdout + result.stderr)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_json_secret_assignment_is_blocked_without_echoing_the_value(self) -> None:
        sensitive_value = "private-" + "runtime-value-123456789"
        secret_key = "api_" + "key"
        self.write("app.txt", json.dumps({"service": {secret_key: sensitive_value}}) + "\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.secret", self.issue_codes(payload))
        self.assertNotIn(sensitive_value, result.stdout + result.stderr)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_prefixed_secret_key_is_blocked_without_echoing_the_value(self) -> None:
        sensitive_value = "private-" + "runtime-value-987654321"
        secret_key = "SERVICE_" + "API_KEY"
        self.write("app.txt", json.dumps({secret_key: sensitive_value}) + "\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.secret", self.issue_codes(payload))
        self.assertNotIn(sensitive_value, result.stdout + result.stderr)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_test_prefixed_secret_value_is_not_treated_as_a_placeholder(self) -> None:
        sensitive_value = "test-" + "private-runtime-value-123456789"
        secret_key = "client_" + "secret"
        self.write("app.txt", json.dumps({secret_key: sensitive_value}) + "\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.secret", self.issue_codes(payload))
        self.assertNotIn(sensitive_value, result.stdout + result.stderr)

    def test_environment_placeholder_is_allowed(self) -> None:
        secret_key = "api_" + "key"
        placeholder = "$" + "{SERVICE_API_KEY}"
        self.write("app.txt", secret_key + "=" + placeholder + "\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "ready")

    def test_local_absolute_user_path_is_blocked(self) -> None:
        separator = chr(92)
        private_path = "C:" + separator + "Users" + separator + "PrivateUser"
        self.write("app.txt", "source=" + private_path + separator + "Desktop\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.local-path", self.issue_codes(payload))
        self.assertNotIn("PrivateUser", result.stdout + result.stderr)

    def test_json_escaped_local_user_path_is_blocked(self) -> None:
        separator = chr(92)
        private_path = "C:" + separator + "Users" + separator + "PrivateUser"
        self.write("app.txt", json.dumps({"source": private_path + separator + "Desktop"}) + "\n")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.local-path", self.issue_codes(payload))
        self.assertNotIn("PrivateUser", result.stdout + result.stderr)

    def test_dirty_index_is_rejected_without_unstaging_user_work(self) -> None:
        run_git(self.repo, "add", "--", "unrelated.txt")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.index-dirty", self.issue_codes(payload))
        staged = run_git(self.repo, "diff", "--cached", "--name-only").stdout.splitlines()
        self.assertEqual(staged, ["unrelated.txt"])

    def test_detached_head_is_rejected(self) -> None:
        run_git(self.repo, "checkout", "--detach")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.detached-head", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_existing_publish_lock_blocks_a_second_publisher(self) -> None:
        git_dir = Path(run_git(self.repo, "rev-parse", "--git-dir").stdout.strip())
        if not git_dir.is_absolute():
            git_dir = self.repo / git_dir
        (git_dir / "github-auto-publisher.lock").write_text("busy\n", encoding="utf-8")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("publish.locked", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_validation_that_mutates_a_scoped_file_is_rejected(self) -> None:
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; Path('app.txt').write_text('changed during check\\n')",
        ]

        result, payload = self.invoke("publish", checks=[command])

        self.assertEqual(result.returncode, 2)
        self.assertIn("validation.changed", self.issue_codes(payload))
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)

    def test_validation_that_creates_a_commit_is_rejected_before_release_commit(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import subprocess; from pathlib import Path; "
                "Path('outside.txt').write_text('outside release\\n'); "
                "subprocess.run(['git', 'add', '--', 'outside.txt'], check=True); "
                "subprocess.run(['git', 'commit', '-m', 'unexpected validation commit'], check=True)"
            ),
        ]

        result, payload = self.invoke("publish", checks=[command])

        self.assertEqual(result.returncode, 2)
        self.assertIn("validation.repository-changed", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)
        committed = run_git(
            self.repo,
            "diff-tree",
            "--no-commit-id",
            "--name-only",
            "-r",
            "HEAD",
        ).stdout.splitlines()
        self.assertEqual(committed, ["outside.txt"])

    def test_remote_ahead_is_rejected_without_pull_or_rebase(self) -> None:
        other = self.root / "other"
        clone = run_process(["git", "clone", "--branch", "main", str(self.remote), str(other)])
        self.assertEqual(clone.returncode, 0, clone.stderr)
        run_git(other, "config", "user.name", "Other Publisher")
        run_git(other, "config", "user.email", "publisher@users.noreply.github.com")
        (other / "upstream.txt").write_text("remote moved\n", encoding="utf-8")
        run_git(other, "add", "--", "upstream.txt")
        run_git(other, "commit", "-m", "remote update")
        run_git(other, "push", "origin", "main")
        advanced_head = run_git(other, "rev-parse", "HEAD").stdout.strip()

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.not-ancestor", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), advanced_head)
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)

    def test_local_ahead_is_rejected_before_release_commit(self) -> None:
        self.write("local-only.txt", "not part of this release\n")
        run_git(self.repo, "add", "--", "local-only.txt")
        run_git(self.repo, "commit", "-m", "local only")
        local_ahead = run_git(self.repo, "rev-parse", "HEAD").stdout.strip()

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.local-ahead", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), local_ahead)

    def test_missing_remote_branch_is_rejected_before_release_commit(self) -> None:
        run_git(self.remote, "update-ref", "-d", "refs/heads/main")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.branch-missing", self.issue_codes(payload))
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)

    def test_distinct_push_url_is_rejected_before_any_remote_write(self) -> None:
        alternate = self.root / "alternate.git"
        run_process(["git", "init", "--bare", str(alternate)])
        run_git(self.repo, "remote", "set-url", "--push", "origin", str(alternate))

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.push-url-mismatch", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)
        self.assertEqual(
            run_git(alternate, "show-ref", "--verify", "--quiet", "refs/heads/main", check=False).returncode,
            1,
        )

    def test_multiple_push_urls_are_rejected_before_any_remote_write(self) -> None:
        alternate = self.root / "alternate.git"
        run_process(["git", "init", "--bare", str(alternate)])
        run_git(self.repo, "remote", "set-url", "--add", "--push", "origin", str(self.remote))
        run_git(self.repo, "remote", "set-url", "--add", "--push", "origin", str(alternate))

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.multiple-pushurl", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)
        self.assertEqual(
            run_git(alternate, "show-ref", "--verify", "--quiet", "refs/heads/main", check=False).returncode,
            1,
        )

    def test_follow_tags_configuration_cannot_publish_an_unrelated_tag(self) -> None:
        run_git(self.repo, "tag", "-a", "unrelated-tag", "-m", "unrelated", self.initial_head)
        run_git(self.repo, "config", "push.followTags", "true")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "pushed")
        tag_result = run_git(
            self.remote,
            "show-ref",
            "--verify",
            "--quiet",
            "refs/tags/unrelated-tag",
            check=False,
        )
        self.assertEqual(tag_result.returncode, 1)

    def test_clean_filter_output_is_scanned_before_commit(self) -> None:
        filter_script = self.write(
            "filter.py",
            "import sys\n"
            "sys.stdin.buffer.read()\n"
            "sys.stdout.write('sk-' + 'a' * 32 + '\\n')\n",
        )
        command = '"' + filter_script.as_posix() + '"'
        python = '"' + Path(sys.executable).as_posix() + '"'
        run_git(self.repo, "config", "filter.inject.clean", python + " " + command)
        run_git(self.repo, "config", "filter.inject.required", "true")
        self.write(".gitattributes", "app.txt filter=inject\n")

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("privacy.secret", self.issue_codes(payload))
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)
        self.assertEqual(run_git(self.repo, "diff", "--cached", "--quiet", check=False).returncode, 0)

    def test_active_post_commit_hook_is_rejected_before_commit(self) -> None:
        hook = self.git_dir() / "hooks" / "post-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        os.chmod(hook, 0o755)

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.hook-present", self.issue_codes(payload))
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_active_hook_in_configured_hooks_path_is_rejected(self) -> None:
        hooks = self.root / "custom-hooks"
        hooks.mkdir()
        hook = hooks / "pre-push"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8", newline="\n")
        os.chmod(hook, 0o755)
        run_git(self.repo, "config", "core.hooksPath", str(hooks))

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.hook-present", self.issue_codes(payload))
        self.assertEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_repository_local_identity_is_required(self) -> None:
        run_git(self.repo, "config", "--local", "--unset", "user.name")
        run_git(self.repo, "config", "--local", "--unset", "user.email")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.identity-missing", self.issue_codes(payload))

    def test_identity_name_must_match_noreply_github_handle(self) -> None:
        run_git(self.repo, "config", "--local", "user.name", "Private Person")

        result, payload = self.invoke("plan")

        self.assertEqual(result.returncode, 2)
        self.assertIn("git.identity-name-not-handle", self.issue_codes(payload))

    def test_publish_invokes_push_once(self) -> None:
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text(
            "#!/bin/sh\n"
            "count=0\n"
            "test -f push-count && count=$(cat push-count)\n"
            "echo $((count + 1)) > push-count\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chmod(hook, 0o755)

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "pushed")
        self.assertEqual((self.remote / "push-count").read_text(encoding="utf-8").strip(), "1")

    def test_remote_readback_mismatch_reports_unconfirmed_without_retry(self) -> None:
        hook = self.remote / "hooks" / "post-receive"
        hook.write_text(
            "#!/bin/sh\n"
            "while read old new ref; do\n"
            "  test \"$ref\" = \"refs/heads/main\" && git update-ref \"$ref\" \"$old\" \"$new\"\n"
            "done\n"
            "exit 0\n",
            encoding="utf-8",
            newline="\n",
        )
        os.chmod(hook, 0o755)

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 3)
        self.assertEqual(payload["status"], "unconfirmed")
        self.assertNotEqual(run_git(self.repo, "rev-parse", "HEAD").stdout.strip(), self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_post_commit_scan_failure_reports_local_commit_only(self) -> None:
        namespace = runpy.run_path(str(PUBLISH))
        original_scan = namespace["scan_git_objects"]
        publish_error = namespace["PublishError"]
        issue = namespace["Issue"]

        def fail_final_scan(settings: Any, commit: str | None) -> None:
            if commit is not None:
                raise publish_error("privacy", issue("privacy.secret", path="app.txt"))
            original_scan(settings, commit)

        namespace["main"].__globals__["scan_git_objects"] = fail_final_scan
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = namespace["main"](self.publisher_args("publish")[2:])
        payload = json.loads(stdout.getvalue())

        local_head = run_git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(exit_code, 3)
        self.assertEqual(payload["status"], "local_commit_only")
        self.assertEqual(payload["commit"], local_head)
        self.assertNotEqual(local_head, self.initial_head)
        self.assertEqual(self.remote_head(), self.initial_head)

    def test_remote_readback_error_after_push_reports_unconfirmed_commit(self) -> None:
        namespace = runpy.run_path(str(PUBLISH))
        original_readback = namespace["remote_branch_sha"]
        publish_error = namespace["PublishError"]
        issue = namespace["Issue"]
        calls = 0

        def fail_post_push_readback(*args: Any, **kwargs: Any) -> str | None:
            nonlocal calls
            calls += 1
            if calls == 4:
                raise publish_error("remote", issue("remote.read-failed"))
            return original_readback(*args, **kwargs)

        namespace["main"].__globals__["remote_branch_sha"] = fail_post_push_readback
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = namespace["main"](self.publisher_args("publish")[2:])
        payload = json.loads(stdout.getvalue())

        local_head = run_git(self.repo, "rev-parse", "HEAD").stdout.strip()
        self.assertEqual(exit_code, 3)
        self.assertEqual(payload["status"], "unconfirmed")
        self.assertEqual(payload["commit"], local_head)
        self.assertEqual(self.remote_head(), local_head)

    def test_credential_bearing_remote_is_blocked_and_redacted(self) -> None:
        remote_value = "secret-" + "value"
        credential_url = "https://publisher:" + remote_value + "@github.com/example/repo.git"
        run_git(
            self.repo,
            "remote",
            "set-url",
            "origin",
            credential_url,
        )

        result, payload = self.invoke("plan", allow_local=False)

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.credentials", self.issue_codes(payload))
        self.assertNotIn(remote_value, result.stdout + result.stderr)

    def test_github_ssh_remote_is_rejected_before_auth_or_network_access(self) -> None:
        ssh_url = "git" + "@" + "github.com:example/repo.git"
        run_git(self.repo, "remote", "set-url", "origin", ssh_url)

        result, payload = self.invoke("plan", allow_local=False)

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.https-required", self.issue_codes(payload))

    def test_github_transport_uses_process_local_cli_credential_helper(self) -> None:
        namespace = runpy.run_path(str(PUBLISH))
        settings = namespace["Settings"](
            mode="plan",
            repo=self.repo,
            remote="origin",
            branch="main",
            message="release: test",
            version_file="VERSION",
            includes=("VERSION", "app.txt"),
            checks=(),
            check_timeout=60,
            allow_non_github_remote=False,
        )
        gh_path = self.root / "GitHub CLI" / "gh.exe"
        target = namespace["RemoteTarget"](
            url="https://github.com/example/repo.git",
            host="github.com",
            gh=str(gh_path),
        )
        captured: dict[str, Any] = {}

        def capture_execute(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(argv, 0, "", "")

        namespace["transport_git"].__globals__["execute"] = capture_execute
        previous_token = os.environ.get("GH_TOKEN")
        try:
            os.environ["GH_TOKEN"] = "runtime-" + "credential-value"
            namespace["transport_git"](
                settings,
                target,
                "ls-remote",
                "--heads",
                settings.remote,
                "refs/heads/main",
            )
        finally:
            if previous_token is None:
                os.environ.pop("GH_TOKEN", None)
            else:
                os.environ["GH_TOKEN"] = previous_token

        argv = captured["argv"]
        environment = captured["env"]
        self.assertIn("credential.helper=", argv)
        self.assertIn("credential.https://github.com.helper=!gh auth git-credential", argv)
        self.assertIn("push.followTags=false", argv)
        self.assertIn("push.gpgSign=false", argv)
        self.assertIn("http.extraHeader=", argv)
        self.assertIn("http.https://github.com/.extraHeader=", argv)
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("GH_TOKEN", environment)
        self.assertTrue(environment["PATH"].startswith(str(gh_path.parent) + os.pathsep))

    def test_url_rewrite_chain_is_rejected_before_any_remote_write(self) -> None:
        alternate = self.root / "alternate.git"
        run_process(["git", "init", "--bare", str(alternate)])
        run_git(self.repo, "push", str(alternate), f"{self.initial_head}:refs/heads/main")
        alias = "publisher-alias://repository"
        remote_url = self.remote.as_uri()
        alternate_url = alternate.as_uri()
        run_git(self.repo, "remote", "set-url", "origin", alias)
        run_git(self.repo, "config", f"url.{remote_url}.insteadOf", alias)
        run_git(self.repo, "config", f"url.{alternate_url}.insteadOf", remote_url)

        result, payload = self.invoke("publish")

        self.assertEqual(result.returncode, 2)
        self.assertIn("remote.url-rewrite", self.issue_codes(payload))
        self.assertEqual(self.remote_head(), self.initial_head)
        alternate_head = run_git(alternate, "rev-parse", "refs/heads/main").stdout.strip()
        self.assertEqual(alternate_head, self.initial_head)

    def test_environment_cannot_override_verified_commit_identity(self) -> None:
        private_email = "private-person" + "@" + "mail.invalid"
        previous_author = os.environ.get("GIT_AUTHOR_EMAIL")
        previous_committer = os.environ.get("GIT_COMMITTER_EMAIL")
        try:
            os.environ["GIT_AUTHOR_EMAIL"] = private_email
            os.environ["GIT_COMMITTER_EMAIL"] = private_email
            result, payload = self.invoke("publish")
        finally:
            if previous_author is None:
                os.environ.pop("GIT_AUTHOR_EMAIL", None)
            else:
                os.environ["GIT_AUTHOR_EMAIL"] = previous_author
            if previous_committer is None:
                os.environ.pop("GIT_COMMITTER_EMAIL", None)
            else:
                os.environ["GIT_COMMITTER_EMAIL"] = previous_committer

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(payload["status"], "pushed")
        metadata = run_git(self.repo, "show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce", "HEAD")
        self.assertEqual(
            metadata.stdout.strip().split("\0"),
            [
                "publisher",
                "publisher@users.noreply.github.com",
                "publisher",
                "publisher@users.noreply.github.com",
            ],
        )
        self.assertNotIn(private_email, metadata.stdout)

    def test_include_outside_repository_is_rejected(self) -> None:
        result, payload = self.invoke("plan", includes=["VERSION", "../outside.txt"])

        self.assertEqual(result.returncode, 2)
        self.assertIn("scope.outside-repository", self.issue_codes(payload))

    def test_skill_sources_do_not_trigger_the_bundled_privacy_scanner(self) -> None:
        namespace = runpy.run_path(str(PUBLISH))
        scan_bytes = namespace["scan_bytes"]
        blocked_path = namespace["blocked_path"]
        files = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "README.md",
            SKILL_ROOT / "CHANGELOG.md",
            SKILL_ROOT / "VERSION",
            SKILL_ROOT / ".gitignore",
            SKILL_ROOT / "agents" / "openai.yaml",
            SKILL_ROOT / "scripts" / "publish.py",
            SKILL_ROOT / "scripts" / "quick_validate.py",
            SKILL_ROOT / "tests" / "test_publish.py",
            SKILL_ROOT / ".github" / "workflows" / "test.yml",
        ]

        detected: list[dict[str, str]] = []
        for path in files:
            relative = path.relative_to(SKILL_ROOT).as_posix()
            if blocked_path(relative):
                detected.append({"code": "privacy.path", "path": relative})
            detected.extend(issue.as_dict() for issue in scan_bytes(relative, path.read_bytes()))

        self.assertEqual(detected, [])


if __name__ == "__main__":
    unittest.main()
