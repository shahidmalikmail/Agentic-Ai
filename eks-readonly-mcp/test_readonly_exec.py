"""Tests for readonly_exec.py's environment-neutral kubectl execution glue.

Every test uses a fake/mock BastionSSHClient - no real SSH connection, no
real kubectl, no PROD contact of any kind. readonly_exec.py delegates all
read-only enforcement to ssh_client.py unchanged; these tests exercise
readonly_exec's own formatting/truncation/error-mapping behavior, injecting
whatever result or exception the fake client is told to produce.
"""
from __future__ import annotations

import ast
import unittest
from unittest.mock import Mock

import readonly_exec
from ssh_client import (
    BastionConnectionError,
    CommandResult,
    CommandTimeoutError,
    ReadOnlyViolation,
)


def _fake_ssh(result=None, raises=None):
    ssh = Mock()
    if raises is not None:
        ssh.run_kubectl.side_effect = raises
    else:
        ssh.run_kubectl.return_value = result
    return ssh


class RunReadonlySuccessTests(unittest.TestCase):
    def test_normal_successful_command_returns_tagged_output(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="POD1\nPOD2\n", stderr="", exit_code=0))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertTrue(out.startswith("[prod]\n"))
        self.assertIn("POD1", out)
        ssh.run_kubectl.assert_called_once_with("kubectl get pods -A -o json")

    def test_empty_output_returns_placeholder_message(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods -n empty", stdout="", stderr="", exit_code=0))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -n empty -o json", tag="prod")
        self.assertIn("(empty result - no matching resources)", out)

    def test_tag_only_labels_response_never_selects_target(self):
        result = CommandResult(command="kubectl get nodes", stdout="NODE1\n", stderr="", exit_code=0)
        ssh_a = _fake_ssh(result=result)
        ssh_b = _fake_ssh(result=result)
        out_a = readonly_exec.run_readonly(ssh_a, "kubectl get nodes -o json", tag="prod")
        out_b = readonly_exec.run_readonly(ssh_b, "kubectl get nodes -o json", tag="some-other-label")
        self.assertTrue(out_a.startswith("[prod]"))
        self.assertTrue(out_b.startswith("[some-other-label]"))
        # Same command sent to whichever ssh object was injected - the tag
        # never appears in the command string itself.
        ssh_a.run_kubectl.assert_called_once_with("kubectl get nodes -o json")
        ssh_b.run_kubectl.assert_called_once_with("kubectl get nodes -o json")


class RunReadonlySanitizerHookTests(unittest.TestCase):
    def test_sanitizer_none_by_default_is_backward_compatible(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="raw-value", stderr="", exit_code=0))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertIn("raw-value", out)

    def test_sanitizer_applied_to_successful_stdout(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="secret-value", stderr="", exit_code=0))
        out = readonly_exec.run_readonly(
            ssh, "kubectl get pods -A -o json", tag="prod", sanitizer=lambda s: s.replace("secret-value", "[REDACTED]")
        )
        self.assertNotIn("secret-value", out)
        self.assertIn("[REDACTED]", out)

    def test_sanitizer_runs_before_truncation(self):
        huge = "x" * (readonly_exec._MAX_OUTPUT_CHARS + 5000)
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout=huge, stderr="", exit_code=0))

        # A sanitizer that shrinks the output drastically - if it ran AFTER
        # truncation instead of before, the truncation marker would appear
        # even though the sanitized text is tiny.
        out = readonly_exec.run_readonly(
            ssh, "kubectl get pods -A -o json", tag="prod", sanitizer=lambda s: "tiny"
        )
        self.assertNotIn("...(output truncated)", out)
        self.assertIn("tiny", out)

    def test_sanitizer_never_applied_on_error_paths(self):
        calls = []
        ssh = _fake_ssh(raises=ReadOnlyViolation("forbidden verb"))
        out = readonly_exec.run_readonly(
            ssh, "kubectl delete pod x", tag="prod", sanitizer=lambda s: calls.append(s) or s
        )
        self.assertEqual(calls, [])
        self.assertIn("blocked by the read-only guard", out)

    def test_sanitizer_never_applied_on_nonzero_exit(self):
        calls = []
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="", stderr="boom", exit_code=1))
        readonly_exec.run_readonly(
            ssh, "kubectl get pods -A -o json", tag="prod", sanitizer=lambda s: calls.append(s) or s
        )
        self.assertEqual(calls, [])


class RunReadonlyTruncationTests(unittest.TestCase):
    def test_output_truncated_beyond_max_chars(self):
        huge = "x" * (readonly_exec._MAX_OUTPUT_CHARS + 5000)
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout=huge, stderr="", exit_code=0))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertIn("...(output truncated)", out)
        body = out.split("\n", 1)[1]
        self.assertLessEqual(len(body), readonly_exec._MAX_OUTPUT_CHARS + len("\n...(output truncated)"))

    def test_output_at_exactly_max_chars_not_truncated(self):
        exact = "y" * readonly_exec._MAX_OUTPUT_CHARS
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout=exact, stderr="", exit_code=0))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertNotIn("...(output truncated)", out)


class RunReadonlyErrorTests(unittest.TestCase):
    def test_kubectl_nonzero_exit_returns_error(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="", stderr="namespaces \"x\" not found", exit_code=1))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -n x -o json", tag="prod")
        self.assertIn("[prod] Error: kubectl failed (exit 1)", out)
        self.assertIn("not found", out)

    def test_read_only_violation_returns_blocked_error(self):
        ssh = _fake_ssh(raises=ReadOnlyViolation("forbidden verb"))
        out = readonly_exec.run_readonly(ssh, "kubectl delete pod x", tag="prod")
        self.assertIn("[prod] Error: this request was blocked by the read-only guard", out)

    def test_bastion_connection_error_returns_error(self):
        ssh = _fake_ssh(raises=BastionConnectionError("could not reach bastion"))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertIn("[prod] Error: could not connect to the bastion", out)

    def test_command_timeout_error_returns_error(self):
        ssh = _fake_ssh(raises=CommandTimeoutError("timed out after 30s"))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertIn("[prod] Error:", out)
        self.assertIn("timed out", out)

    def test_stderr_empty_uses_placeholder(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get pods", stdout="", stderr="", exit_code=2))
        out = readonly_exec.run_readonly(ssh, "kubectl get pods -A -o json", tag="prod")
        self.assertIn("(no stderr output)", out)


class InjectedClientTests(unittest.TestCase):
    def test_run_readonly_calls_injected_client_exactly_once(self):
        ssh = _fake_ssh(result=CommandResult(command="kubectl get nodes", stdout="ok", stderr="", exit_code=0))
        readonly_exec.run_readonly(ssh, "kubectl get nodes -o json", tag="prod")
        self.assertEqual(ssh.run_kubectl.call_count, 1)

    def test_run_readonly_never_constructs_its_own_ssh_client(self):
        with open("readonly_exec.py", encoding="utf-8") as f:
            source = ast.parse(f.read())
        names_called = {
            node.func.id
            for node in ast.walk(source)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("BastionSSHClient", names_called)


class NamespaceValidationTests(unittest.TestCase):
    def test_none_namespace_scopes_all(self):
        self.assertEqual(readonly_exec.scope_args(None), "-A")

    def test_all_keyword_scopes_all(self):
        self.assertEqual(readonly_exec.scope_args("all"), "-A")
        self.assertEqual(readonly_exec.scope_args("ALL"), "-A")

    def test_specific_namespace_scoped(self):
        self.assertEqual(readonly_exec.scope_args("commerce"), "-n commerce")

    def test_invalid_namespace_raises_value_error(self):
        with self.assertRaises(ValueError):
            readonly_exec.scope_args("Not_Valid!")

    def test_shell_metacharacters_in_namespace_rejected(self):
        with self.assertRaises(ValueError):
            readonly_exec.scope_args("default; rm -rf /")


class ModuleIndependenceTests(unittest.TestCase):
    """readonly_exec.py must stay environment-neutral: no config.py import,
    no kube_core.py import, no environment-selection concept."""

    def _imports(self) -> set[str]:
        with open("readonly_exec.py", encoding="utf-8") as f:
            tree = ast.parse(f.read())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        return imported

    def test_does_not_import_config(self):
        self.assertNotIn("config", self._imports())

    def test_does_not_import_kube_core(self):
        self.assertNotIn("kube_core", self._imports())

    def test_no_env_parameter_anywhere_in_module(self):
        with open("readonly_exec.py", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                arg_names = {a.arg for a in node.args.args}
                self.assertNotIn("env", arg_names, f"{node.name} must not accept an env parameter")


if __name__ == "__main__":
    unittest.main()
