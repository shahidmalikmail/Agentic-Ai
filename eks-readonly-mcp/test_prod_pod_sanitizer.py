"""Tests for prod_pod_sanitizer.py.

Pure unit tests against representative FAKE Kubernetes pod JSON only -
never real PROD output, per the P10.1 instructions. No SSH, no kubectl, no
PROD contact of any kind; this module has no I/O at all.
"""
from __future__ import annotations

import json
import unittest

import prod_pod_sanitizer


def _pod(
    name="checkout-7d9",
    namespace="commerce",
    env=None,
    env_from=None,
    extra_container_fields=None,
):
    container = {
        "name": "checkout",
        "image": "registry.internal/checkout:1.4.2",
        "ready": True,
        "restartCount": 0,
        "state": {"running": {"startedAt": "2026-09-01T00:00:00Z"}},
        "resources": {"limits": {"cpu": "500m", "memory": "512Mi"}},
    }
    if env is not None:
        container["env"] = env
    if env_from is not None:
        container["envFrom"] = env_from
    if extra_container_fields:
        container.update(extra_container_fields)

    return {
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": {"app": "checkout"}},
        "spec": {
            "nodeName": "ip-10-13-1-20.ec2.internal",
            "containers": [container],
        },
        "status": {
            "phase": "Running",
            "podIP": "10.13.4.55",
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [
                {"name": "checkout", "ready": True, "restartCount": 0, "image": container["image"]}
            ],
        },
    }


def _pod_list(*pods):
    return {"kind": "PodList", "apiVersion": "v1", "items": list(pods)}


class BasicRedactionTests(unittest.TestCase):
    def test_env_value_redacted(self):
        raw = json.dumps(
            _pod_list(_pod(env=[{"name": "DB_PASSWORD", "value": "hunter2-super-secret"}]))
        )
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("hunter2-super-secret", out)
        data = json.loads(out)
        env = data["items"][0]["spec"]["containers"][0]["env"]
        self.assertEqual(env, "[REDACTED]")

    def test_env_from_secret_ref_redacted(self):
        raw = json.dumps(
            _pod_list(
                _pod(env_from=[{"secretRef": {"name": "checkout-db-creds"}}])
            )
        )
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("checkout-db-creds", out)
        data = json.loads(out)
        self.assertEqual(data["items"][0]["spec"]["containers"][0]["envFrom"], "[REDACTED]")

    def test_env_from_configmap_ref_redacted(self):
        raw = json.dumps(
            _pod_list(_pod(env_from=[{"configMapRef": {"name": "checkout-config"}}]))
        )
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("checkout-config", out)

    def test_secret_key_ref_redacted(self):
        env = [
            {
                "name": "JDBC_PASSWORD",
                "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}},
            }
        ]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("db-secret", out)
        self.assertNotIn("secretKeyRef", out)

    def test_config_map_key_ref_redacted(self):
        env = [
            {
                "name": "FEATURE_FLAG",
                "valueFrom": {"configMapKeyRef": {"name": "app-config", "key": "flag"}},
            }
        ]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("configMapKeyRef", out)

    def test_field_ref_redacted(self):
        env = [{"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}}]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("fieldRef", out)

    def test_init_containers_also_sanitized(self):
        pod = _pod()
        pod["spec"]["initContainers"] = [
            {"name": "migrate", "image": "registry.internal/migrate:1.0", "env": [{"name": "DB_URL", "value": "postgres://real-host/db"}]}
        ]
        raw = json.dumps(_pod_list(pod))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("postgres://real-host/db", out)
        data = json.loads(out)
        self.assertEqual(data["items"][0]["spec"]["initContainers"][0]["env"], "[REDACTED]")


class NamedSensitiveValueTests(unittest.TestCase):
    """Every listed sensitive-sounding variable name, plus (critically) a
    plain-looking one, all removed identically - proving this is NOT a
    keyword/name-based filter."""

    _CASES = {
        "PASSWORD": "p@ssw0rd-value",
        "DB_PASSWORD": "db-p@ssw0rd-value",
        "TOKEN": "tok-abc123",
        "API_KEY": "ak-abc123",
        "SECRET": "sekret-value",
        "AWS_ACCESS_KEY_ID": "AKIAFAKEEXAMPLE0001",
        "AWS_SECRET_ACCESS_KEY": "fakeSecretAccessKeyExampleValue000000000",
        "JDBC_PASSWORD": "jdbc-p@ss",
        "AUTH_TOKEN": "auth-tok-xyz",
        # Deliberately ordinary-looking names - must be redacted identically.
        "SOME_VARIABLE": "just-a-normal-looking-value",
        "LOG_LEVEL": "DEBUG",
    }

    def test_all_named_values_absent_and_env_replaced_wholesale(self):
        env = [{"name": name, "value": value} for name, value in self._CASES.items()]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)

        for value in self._CASES.values():
            self.assertNotIn(value, out)

        data = json.loads(out)
        self.assertEqual(data["items"][0]["spec"]["containers"][0]["env"], "[REDACTED]")

    def test_variable_names_themselves_may_appear_but_never_their_values(self):
        # The sanitizer redacts the whole env block, so names disappear
        # too (env == "[REDACTED]") - this asserts the stronger property
        # actually implemented, not merely "values gone, names visible".
        env = [{"name": "DB_PASSWORD", "value": "should-not-appear-1234"}]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("DB_PASSWORD", out)
        self.assertNotIn("should-not-appear-1234", out)


class NegativeCaseTests(unittest.TestCase):
    def test_fake_secret_value_absent_from_output(self):
        env = [{"name": "SOME_SECRET", "value": "SUPER_SECRET_TEST_VALUE_12345"}]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("SUPER_SECRET_TEST_VALUE_12345", out)

    def test_fake_vault_token_absent_from_output(self):
        env = [
            {"name": "VAULT_TOKEN", "value": "hvs.FAKE0000TOKEN0000EXAMPLE0000NOTREAL"},
            {"name": "VAULT_ADDR", "value": "https://vault.internal.example:8200"},
        ]
        raw = json.dumps(_pod_list(_pod(env=env)))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("hvs.FAKE0000TOKEN0000EXAMPLE0000NOTREAL", out)
        self.assertNotIn("https://vault.internal.example:8200", out)


class OperationalFieldsPreservedTests(unittest.TestCase):
    def test_metadata_and_status_and_container_fields_survive(self):
        raw = json.dumps(
            _pod_list(_pod(env=[{"name": "X", "value": "y"}], namespace="commerce", name="checkout-7d9"))
        )
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        data = json.loads(out)
        pod = data["items"][0]

        self.assertEqual(pod["metadata"]["name"], "checkout-7d9")
        self.assertEqual(pod["metadata"]["namespace"], "commerce")
        self.assertEqual(pod["status"]["phase"], "Running")
        self.assertEqual(pod["status"]["conditions"], [{"type": "Ready", "status": "True"}])
        self.assertEqual(pod["status"]["podIP"], "10.13.4.55")
        self.assertEqual(pod["spec"]["nodeName"], "ip-10-13-1-20.ec2.internal")

        container = pod["spec"]["containers"][0]
        self.assertEqual(container["name"], "checkout")
        self.assertEqual(container["image"], "registry.internal/checkout:1.4.2")
        self.assertIn("state", container)
        self.assertEqual(container["resources"], {"limits": {"cpu": "500m", "memory": "512Mi"}})

        container_status = pod["status"]["containerStatuses"][0]
        self.assertEqual(container_status["ready"], True)
        self.assertEqual(container_status["restartCount"], 0)

    def test_container_with_no_env_at_all_untouched(self):
        raw = json.dumps(_pod_list(_pod()))  # no env/envFrom passed
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        data = json.loads(out)
        container = data["items"][0]["spec"]["containers"][0]
        self.assertNotIn("env", container)
        self.assertNotIn("envFrom", container)

    def test_multiple_pods_each_sanitized_independently(self):
        pod_a = _pod(name="a", env=[{"name": "X", "value": "secret-a"}])
        pod_b = _pod(name="b", env=[{"name": "Y", "value": "secret-b"}])
        raw = json.dumps(_pod_list(pod_a, pod_b))
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("secret-a", out)
        self.assertNotIn("secret-b", out)
        data = json.loads(out)
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["items"][0]["metadata"]["name"], "a")
        self.assertEqual(data["items"][1]["metadata"]["name"], "b")


class ShapeAndFailClosedTests(unittest.TestCase):
    def test_empty_pod_list_passes_through(self):
        raw = json.dumps(_pod_list())
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        data = json.loads(out)
        self.assertEqual(data["items"], [])

    def test_single_pod_object_shape_also_sanitized(self):
        pod = _pod(env=[{"name": "X", "value": "single-pod-secret"}])
        raw = json.dumps(pod)
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotIn("single-pod-secret", out)
        data = json.loads(out)
        self.assertEqual(data["spec"]["containers"][0]["env"], "[REDACTED]")

    def test_malformed_json_fails_closed(self):
        out = prod_pod_sanitizer.sanitize_pod_list_json("{not valid json")
        data = json.loads(out)
        self.assertIn("error", data)
        self.assertNotIn("not valid json", out)

    def test_unexpected_shape_fails_closed(self):
        raw = json.dumps({"kind": "Namespace", "metadata": {"name": "commerce"}})
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        data = json.loads(out)
        self.assertIn("error", data)

    def test_non_dict_top_level_fails_closed(self):
        out = prod_pod_sanitizer.sanitize_pod_list_json(json.dumps([1, 2, 3]))
        data = json.loads(out)
        self.assertIn("error", data)

    def test_items_containing_non_dict_entries_does_not_crash(self):
        raw = json.dumps({"kind": "PodList", "items": [None, "not-a-pod", 42]})
        out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        data = json.loads(out)
        self.assertEqual(data["items"], [None, "not-a-pod", 42])


def _container(name="app", image="registry.internal/app:1.0", env=None, env_from=None):
    container = {
        "name": name,
        "image": image,
        "resources": {"limits": {"cpu": "250m", "memory": "256Mi"}},
        "ports": [{"containerPort": 8080}],
    }
    if env is not None:
        container["env"] = env
    if env_from is not None:
        container["envFrom"] = env_from
    return container


def _workload(
    kind,
    name="checkout",
    namespace="commerce",
    containers=None,
    init_containers=None,
    replicas=3,
    ready_replicas=3,
):
    obj = {
        "kind": kind,
        "apiVersion": "apps/v1",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {"app": name},
            "annotations": {"team": "commerce"},
        },
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name}},
                "spec": {
                    "containers": containers or [_container()],
                },
            },
        },
        "status": {
            "replicas": replicas,
            "readyReplicas": ready_replicas,
            "availableReplicas": ready_replicas,
            "updatedReplicas": replicas,
            "conditions": [{"type": "Available", "status": "True"}],
        },
    }
    if init_containers is not None:
        obj["spec"]["template"]["spec"]["initContainers"] = init_containers
    return obj


def _workload_list(kind, *items):
    return {"kind": f"{kind}List", "apiVersion": "apps/v1", "items": list(items)}


class WorkloadRedactionTests(unittest.TestCase):
    _KINDS = ("Deployment", "ReplicaSet", "StatefulSet", "DaemonSet")

    def test_containers_env_redacted_for_every_kind(self):
        for kind in self._KINDS:
            with self.subTest(kind=kind):
                containers = [
                    _container(env=[{"name": "DB_PASSWORD", "value": "FAKE_DB_PASSWORD_12345"}])
                ]
                raw = json.dumps(_workload_list(kind, _workload(kind, containers=containers)))
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                self.assertNotIn("FAKE_DB_PASSWORD_12345", out)
                data = json.loads(out)
                item = data["items"][0]
                env = item["spec"]["template"]["spec"]["containers"][0]["env"]
                self.assertEqual(env, "[REDACTED]")

    def test_containers_env_from_redacted_for_every_kind(self):
        for kind in self._KINDS:
            with self.subTest(kind=kind):
                containers = [_container(env_from=[{"secretRef": {"name": "checkout-secret"}}])]
                raw = json.dumps(_workload_list(kind, _workload(kind, containers=containers)))
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                self.assertNotIn("checkout-secret", out)
                self.assertNotIn("secretRef", out)

    def test_init_containers_env_and_env_from_redacted_for_every_kind(self):
        for kind in self._KINDS:
            with self.subTest(kind=kind):
                init_containers = [
                    _container(
                        name="migrate",
                        env=[{"name": "MIGRATE_TOKEN", "value": "FAKE_VAULT_TOKEN_12345"}],
                        env_from=[{"configMapRef": {"name": "migrate-config"}}],
                    )
                ]
                raw = json.dumps(
                    _workload_list(kind, _workload(kind, init_containers=init_containers))
                )
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                self.assertNotIn("FAKE_VAULT_TOKEN_12345", out)
                self.assertNotIn("migrate-config", out)
                data = json.loads(out)
                init = data["items"][0]["spec"]["template"]["spec"]["initContainers"][0]
                self.assertEqual(init["env"], "[REDACTED]")
                self.assertEqual(init["envFrom"], "[REDACTED]")

    def test_secret_key_ref_and_config_map_key_ref_redacted_for_every_kind(self):
        for kind in self._KINDS:
            with self.subTest(kind=kind):
                env = [
                    {
                        "name": "JDBC_PASSWORD",
                        "valueFrom": {"secretKeyRef": {"name": "db-secret", "key": "password"}},
                    },
                    {
                        "name": "FLAG",
                        "valueFrom": {"configMapKeyRef": {"name": "app-config", "key": "flag"}},
                    },
                ]
                raw = json.dumps(
                    _workload_list(kind, _workload(kind, containers=[_container(env=env)]))
                )
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                self.assertNotIn("db-secret", out)
                self.assertNotIn("app-config", out)
                self.assertNotIn("secretKeyRef", out)
                self.assertNotIn("configMapKeyRef", out)


class WorkloadNamedSensitiveValueTests(unittest.TestCase):
    """Proves the workload sanitizer, like the pod one, is NOT a
    keyword/name-based filter - an ordinary-looking name is redacted
    identically to an obviously sensitive one."""

    def test_ordinary_looking_variable_name_still_redacted(self):
        for kind in ("Deployment", "ReplicaSet", "StatefulSet", "DaemonSet"):
            with self.subTest(kind=kind):
                env = [{"name": "APP_SETTING", "value": "SUPER_SECRET_TEST_VALUE_12345"}]
                raw = json.dumps(
                    _workload_list(kind, _workload(kind, containers=[_container(env=env)]))
                )
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                self.assertNotIn("SUPER_SECRET_TEST_VALUE_12345", out)
                self.assertNotIn("APP_SETTING", out)


class WorkloadOperationalFieldsPreservedTests(unittest.TestCase):
    def test_metadata_replicas_selector_template_labels_and_status_survive(self):
        for kind in ("Deployment", "ReplicaSet", "StatefulSet", "DaemonSet"):
            with self.subTest(kind=kind):
                containers = [_container(env=[{"name": "X", "value": "y"}])]
                obj = _workload(kind, name="checkout", namespace="commerce", containers=containers)
                raw = json.dumps(_workload_list(kind, obj))
                out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
                data = json.loads(out)
                item = data["items"][0]

                self.assertEqual(item["metadata"]["name"], "checkout")
                self.assertEqual(item["metadata"]["namespace"], "commerce")
                self.assertEqual(item["metadata"]["labels"], {"app": "checkout"})
                self.assertEqual(item["spec"]["replicas"], 3)
                self.assertEqual(item["spec"]["selector"], {"matchLabels": {"app": "checkout"}})
                self.assertEqual(item["spec"]["template"]["metadata"]["labels"], {"app": "checkout"})

                container = item["spec"]["template"]["spec"]["containers"][0]
                self.assertEqual(container["name"], "app")
                self.assertEqual(container["image"], "registry.internal/app:1.0")
                self.assertEqual(container["resources"], {"limits": {"cpu": "250m", "memory": "256Mi"}})
                self.assertEqual(container["ports"], [{"containerPort": 8080}])

                self.assertEqual(item["status"]["replicas"], 3)
                self.assertEqual(item["status"]["readyReplicas"], 3)
                self.assertEqual(item["status"]["availableReplicas"], 3)
                self.assertEqual(item["status"]["updatedReplicas"], 3)
                self.assertEqual(item["status"]["conditions"], [{"type": "Available", "status": "True"}])

    def test_container_with_no_env_untouched(self):
        raw = json.dumps(_workload_list("Deployment", _workload("Deployment")))
        out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
        data = json.loads(out)
        container = data["items"][0]["spec"]["template"]["spec"]["containers"][0]
        self.assertNotIn("env", container)
        self.assertNotIn("envFrom", container)


class WorkloadShapeAndFailClosedTests(unittest.TestCase):
    def test_single_workload_object_shape_also_sanitized(self):
        obj = _workload("Deployment", containers=[_container(env=[{"name": "X", "value": "single-obj-secret"}])])
        out = prod_pod_sanitizer.sanitize_workload_list_json(json.dumps(obj))
        self.assertNotIn("single-obj-secret", out)
        data = json.loads(out)
        self.assertEqual(data["spec"]["template"]["spec"]["containers"][0]["env"], "[REDACTED]")

    def test_malformed_json_fails_closed(self):
        out = prod_pod_sanitizer.sanitize_workload_list_json("{not valid json")
        data = json.loads(out)
        self.assertIn("error", data)

    def test_pod_list_rejected_by_workload_sanitizer(self):
        # Pod/PodList is explicitly NOT a supported kind for this entry
        # point - sanitize_pod_list_json() exists for that shape. Fails
        # closed rather than silently no-op-ing on an unrecognized kind.
        raw = json.dumps(_pod_list(_pod(env=[{"name": "X", "value": "y"}])))
        out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
        data = json.loads(out)
        self.assertIn("error", data)

    def test_unrelated_kind_fails_closed(self):
        raw = json.dumps({"kind": "ConfigMap", "metadata": {"name": "x"}})
        out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
        data = json.loads(out)
        self.assertIn("error", data)

    def test_non_dict_top_level_fails_closed(self):
        out = prod_pod_sanitizer.sanitize_workload_list_json(json.dumps([1, 2, 3]))
        data = json.loads(out)
        self.assertIn("error", data)

    def test_empty_items_list_passes_through(self):
        raw = json.dumps(_workload_list("Deployment"))
        out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
        data = json.loads(out)
        self.assertEqual(data["items"], [])

    def test_multiple_items_each_sanitized_independently(self):
        a = _workload("Deployment", name="a", containers=[_container(env=[{"name": "X", "value": "secret-a"}])])
        b = _workload("Deployment", name="b", containers=[_container(env=[{"name": "Y", "value": "secret-b"}])])
        raw = json.dumps(_workload_list("Deployment", a, b))
        out = prod_pod_sanitizer.sanitize_workload_list_json(raw)
        self.assertNotIn("secret-a", out)
        self.assertNotIn("secret-b", out)
        data = json.loads(out)
        self.assertEqual(len(data["items"]), 2)


class SuccessPathEmitsNoDiagnosticTests(unittest.TestCase):
    """Scenarios 1, 2, 15, 16: successful sanitization never logs anything,
    including with realistic whitespace variations."""

    _LOGGER_NAME = "prod-pod-sanitizer"

    def test_1_valid_pod_list_emits_no_diagnostic(self):
        raw = json.dumps(_pod_list(_pod()))
        with self.assertNoLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)

    def test_2_valid_pod_emits_no_diagnostic(self):
        raw = json.dumps(_pod())
        with self.assertNoLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)

    def test_15_pod_list_with_trailing_newline_emits_no_diagnostic(self):
        raw = json.dumps(_pod_list(_pod())) + "\n"
        with self.assertNoLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)

    def test_16_pod_list_with_leading_whitespace_emits_no_diagnostic(self):
        raw = "  \n" + json.dumps(_pod_list(_pod()))
        with self.assertNoLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertNotEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)

    def test_17_pod_list_with_harmless_stderr_via_real_run_readonly(self):
        # Exercises the REAL readonly_exec.run_readonly() + real sanitizer,
        # proving stderr presence (with exit_code=0) has zero effect on the
        # sanitizer's input or on whether a diagnostic fires.
        from unittest.mock import Mock

        import readonly_exec
        from ssh_client import CommandResult

        ssh = Mock()
        ssh.run_kubectl.return_value = CommandResult(
            command="kubectl get pods -n commerce -o json",
            stdout=json.dumps(_pod_list(_pod())),
            stderr="Warning: some harmless notice\n",
            exit_code=0,
        )
        with self.assertNoLogs(self._LOGGER_NAME, level="WARNING"):
            out = readonly_exec.run_readonly(
                ssh, "kubectl get pods -n commerce -o json", tag="prod",
                sanitizer=prod_pod_sanitizer.sanitize_pod_list_json,
            )
        self.assertNotIn("withheld", out)


class UnexpectedShapeDiagnosticTests(unittest.TestCase):
    """Scenarios 3-11, 18-22: sanitize_pod_list_json()'s fail-closed
    unexpected-shape diagnostic (P10.3B, extended by P10.3F). Every
    assertion proves both what IS logged (a fixed, safe vocabulary) and
    what is NEVER logged (payload, arbitrary values, secrets)."""

    _LOGGER_NAME = "prod-pod-sanitizer"

    def _sanitize_and_capture(self, raw):
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)
        return "\n".join(cm.output)

    # --- 3/4: Status / APIStatus-like ---

    def test_3_status_object_logs_unrecognized_kind(self):
        joined = self._sanitize_and_capture(json.dumps({"kind": "Status", "status": "Success", "code": 200}))
        self.assertIn("json_type=dict", joined)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertNotIn("Status", joined.replace("json_type=", "").replace("kind_named=", ""))

    def test_4_apistatus_like_object_logs_unrecognized_kind(self):
        joined = self._sanitize_and_capture(json.dumps({"kind": "APIStatus", "message": "x"}))
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertNotIn("APIStatus", joined)
        self.assertNotIn("message", joined)

    # --- 21: recognized-but-not-Pod/PodList kind ---

    def test_21_recognized_non_pod_kind_names_only_the_allowlisted_kind(self):
        raw = json.dumps({"kind": "Deployment", "metadata": {"name": "should-not-appear"}})
        joined = self._sanitize_and_capture(raw)
        self.assertIn("kind_named=Deployment", joined)
        self.assertIn("kind_recognized=True", joined)
        self.assertNotIn("should-not-appear", joined)
        self.assertNotIn("<UNRECOGNIZED>", joined)

    def test_every_recognized_kind_can_be_named(self):
        for kind in sorted(prod_pod_sanitizer._RECOGNIZED_KINDS - {"Pod", "PodList"}):
            with self.subTest(kind=kind):
                joined = self._sanitize_and_capture(json.dumps({"kind": kind}))
                self.assertIn(f"kind_named={kind}", joined)
                self.assertIn("kind_recognized=True", joined)

    # --- 5/22: arbitrary/unrecognized kind - name is NEVER logged ---

    def test_5_and_22_unrecognized_kind_logs_placeholder_not_actual_value(self):
        raw = json.dumps({"kind": "TotallyMadeUpKind123"})
        joined = self._sanitize_and_capture(raw)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertIn("kind_recognized=False", joined)
        self.assertNotIn("TotallyMadeUpKind123", joined)

    # --- 6/20: dict without kind, no items ---

    def test_6_and_20_missing_kind_key_and_no_items(self):
        raw = json.dumps({"apiVersion": "v1"})
        joined = self._sanitize_and_capture(raw)
        self.assertIn("kind_present=False", joined)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertIn("items_present=False", joined)
        self.assertIn("items_is_list=False", joined)
        self.assertNotIn("items_count=", joined)

    def test_non_string_kind_value_logs_unrecognized(self):
        joined = self._sanitize_and_capture(json.dumps({"kind": 12345}))
        self.assertIn("kind_is_string=False", joined)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertNotIn("12345", joined)

    # --- 7-11: non-dict JSON values, each with its own specific json_type ---

    def test_7_json_list_logs_specific_type(self):
        joined = self._sanitize_and_capture(json.dumps([1, 2, 3]))
        self.assertIn("json_type=list", joined)
        self.assertNotIn("1, 2, 3", joined)
        self.assertNotIn("kind_", joined)
        self.assertNotIn("items_", joined)

    def test_8_json_string_logs_specific_type(self):
        joined = self._sanitize_and_capture(json.dumps("just a string, not a dict"))
        self.assertIn("json_type=string", joined)
        self.assertNotIn("just a string", joined)

    def test_9_json_number_logs_specific_type(self):
        joined = self._sanitize_and_capture(json.dumps(42))
        self.assertIn("json_type=number", joined)
        self.assertNotIn("42", joined.replace("stdout_length=2", ""))

    def test_10_json_boolean_logs_specific_type(self):
        joined = self._sanitize_and_capture(json.dumps(True))
        self.assertIn("json_type=bool", joined)

    def test_11_json_null_logs_specific_type(self):
        joined = self._sanitize_and_capture("null")
        self.assertIn("json_type=null", joined)

    # --- 18/19: items field variations ---

    def test_18_items_present_and_list_reports_count(self):
        raw = json.dumps({"kind": "Widget", "items": [1, 2, 3, 4]})
        joined = self._sanitize_and_capture(raw)
        self.assertIn("items_present=True", joined)
        self.assertIn("items_is_list=True", joined)
        self.assertIn("items_count=4", joined)

    def test_19_items_present_but_non_list_omits_count(self):
        raw = json.dumps({"kind": "Widget", "items": "not-a-list"})
        joined = self._sanitize_and_capture(raw)
        self.assertIn("items_present=True", joined)
        self.assertIn("items_is_list=False", joined)
        self.assertNotIn("items_count=", joined)
        self.assertNotIn("not-a-list", joined)

    # --- pre-parse fields are present on the unexpected-shape path too ---

    def test_pre_parse_fields_present_on_unexpected_shape_path(self):
        raw = json.dumps({"kind": "Widget"}) + "\n"
        joined = self._sanitize_and_capture(raw)
        self.assertIn("stdout_length=", joined)
        self.assertIn("has_leading_whitespace=False", joined)
        self.assertIn("has_trailing_whitespace=True", joined)
        self.assertIn("starts_with=object", joined)


class MalformedJsonDiagnosticTests(unittest.TestCase):
    """Scenarios 12-14: the malformed-JSON path now emits a diagnostic
    (P10.3F), but ONLY the approved pre-parse fields - never json_type,
    kind_*, items_*, the exception text, or any payload substring."""

    _LOGGER_NAME = "prod-pod-sanitizer"

    def _sanitize_and_capture(self, raw):
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        self.assertEqual(out, prod_pod_sanitizer._WITHHELD_UNPARSABLE)
        return "\n".join(cm.output)

    def test_12_malformed_json_emits_pre_parse_fields_only(self):
        joined = self._sanitize_and_capture("{not valid json")
        self.assertIn("stdout_length=15", joined)
        self.assertIn("has_leading_whitespace=False", joined)
        self.assertIn("has_trailing_whitespace=False", joined)
        self.assertIn("starts_with=object", joined)
        # G: only pre-parse fields - never post-parse fields, which don't
        # even make sense here since parsing never succeeded.
        self.assertNotIn("json_type=", joined)
        self.assertNotIn("kind_", joined)
        self.assertNotIn("items_", joined)

    def test_13_empty_string_reports_starts_with_empty(self):
        joined = self._sanitize_and_capture("")
        self.assertIn("stdout_length=0", joined)
        self.assertIn("starts_with=empty", joined)

    def test_14_whitespace_only_string_reports_starts_with_empty(self):
        joined = self._sanitize_and_capture("   \n\t  ")
        self.assertIn("starts_with=empty", joined)
        self.assertIn("has_leading_whitespace=True", joined)
        self.assertIn("has_trailing_whitespace=True", joined)

    def test_malformed_json_with_leading_and_trailing_whitespace(self):
        joined = self._sanitize_and_capture("  \n{not valid  \n")
        self.assertIn("has_leading_whitespace=True", joined)
        self.assertIn("has_trailing_whitespace=True", joined)

    def test_c_exception_text_never_logged(self):
        # A JSONDecodeError's own message typically includes a snippet of
        # the offending text and a "line N column N (char N)" locator -
        # both must be structurally absent, since _log_malformed_json
        # never even receives the exception object.
        distinctive = "UNIQUE_MALFORMED_MARKER_98765"
        raw = "{" + distinctive
        joined = self._sanitize_and_capture(raw)
        self.assertNotIn(distinctive, joined)
        self.assertNotIn("line 1 column", joined)
        self.assertNotIn("char ", joined)

    def test_starts_with_digit_for_bare_number_like_malformed_text(self):
        joined = self._sanitize_and_capture("123abc")
        self.assertIn("starts_with=digit_or_minus_or_other", joined)

    def test_starts_with_each_fixed_enum_value(self):
        cases = {
            "{broken": "object",
            "[broken": "array",
            '"broken': "string",
            "trueish_but_broken": "true",
            "falseish_but_broken": "false",
            "nullish_but_broken": "null",
            "-broken": "digit_or_minus_or_other",
            "9broken": "digit_or_minus_or_other",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                joined = self._sanitize_and_capture(raw)
                self.assertIn(f"starts_with={expected}", joined)


class DiagnosticSecurityTests(unittest.TestCase):
    """Security requirements A, B, C (cross-checked), D, E, F, G, H, I -
    consolidated cross-cutting proofs that no sentinel/arbitrary/secret
    value or the raw payload ever appears in any diagnostic log line, and
    that the MCP response contract is unaffected."""

    _LOGGER_NAME = "prod-pod-sanitizer"

    _SENTINELS = ("SENSITIVE_SENTINEL_12345", "SECRET_SENTINEL_67890", "TOKEN_SENTINEL_ABCDE")

    # --- A/I: sentinel/arbitrary payload-derived strings never logged ---

    def test_a_sentinels_absent_from_unexpected_shape_diagnostics(self):
        raw = json.dumps(
            {
                "kind": "WeirdUnknownThing",
                "apiToken": self._SENTINELS[0],
                "password": self._SENTINELS[1],
                "vaultToken": self._SENTINELS[2],
                "items": [self._SENTINELS[0]],
            }
        )
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json(raw)
        joined = "\n".join(cm.output)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        for sentinel in self._SENTINELS:
            self.assertNotIn(sentinel, joined)
        self.assertNotIn("WeirdUnknownThing", joined)

    def test_a_sentinels_absent_from_malformed_json_diagnostics(self):
        raw = "{" + self._SENTINELS[0] + ": broken"
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json(raw)
        joined = "\n".join(cm.output)
        self.assertNotIn(self._SENTINELS[0], joined)

    # --- B: arbitrary kind values never logged ---

    def test_b_arbitrary_kind_value_never_logged(self):
        raw = json.dumps({"kind": "VerySensitiveFakeKindName"})
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json(raw)
        joined = "\n".join(cm.output)
        self.assertIn("kind_named=<UNRECOGNIZED>", joined)
        self.assertNotIn("VerySensitiveFakeKindName", joined)

    # --- D: fixed fail-closed response text itself never changes ---

    def test_d_fixed_placeholder_constants_unchanged(self):
        self.assertEqual(
            prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE,
            json.dumps(
                {
                    "error": "PROD Kubernetes data had an unexpected or unsupported shape and was withheld before being returned."
                }
            ),
        )
        self.assertEqual(
            prod_pod_sanitizer._WITHHELD_UNPARSABLE,
            json.dumps(
                {"error": "PROD Kubernetes data could not be safely parsed and was withheld before being returned."}
            ),
        )

    # --- E: diagnostics never become the function return value ---

    def test_e_unexpected_shape_diagnostic_never_returned(self):
        raw = json.dumps({"kind": "TotallyMadeUpKind123", "items": [1, 2, 3]})
        with self.assertLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json(raw)
        for token in ("TotallyMadeUpKind123", "kind_named=", "items_count=", "stdout_length="):
            self.assertNotIn(token, out)
        self.assertEqual(out, prod_pod_sanitizer._WITHHELD_UNEXPECTED_SHAPE)

    def test_e_malformed_diagnostic_never_returned(self):
        with self.assertLogs(self._LOGGER_NAME, level="WARNING"):
            out = prod_pod_sanitizer.sanitize_pod_list_json("{not valid json")
        self.assertNotIn("stdout_length=", out)
        self.assertNotIn("starts_with=", out)
        self.assertEqual(out, prod_pod_sanitizer._WITHHELD_UNPARSABLE)

    # --- H: every logged value is a bool, an int, or a small fixed token ---

    _ALLOWED_VALUE_PATTERN_BY_KEY = {
        "stdout_length": r"\d+",
        "has_leading_whitespace": r"True|False",
        "has_trailing_whitespace": r"True|False",
        "starts_with": r"object|array|string|true|false|null|digit_or_minus_or_other|empty",
        "json_type": r"dict|list|string|number|bool|null|other",
        "kind_present": r"True|False",
        "kind_is_string": r"True|False",
        "kind_recognized": r"True|False",
        "items_present": r"True|False",
        "items_is_list": r"True|False",
        "items_count": r"\d+",
    }

    def _assert_all_tokens_well_formed(self, line: str) -> None:
        import re

        # Strip the fixed "sanitize_pod_list_json: <reason> - " prefix,
        # leaving only the space-separated key=value tokens.
        payload = line.split(" - ", 1)[1] if " - " in line else line
        for token in payload.split():
            self.assertIn("=", token, f"malformed diagnostic token: {token!r}")
            key, _, value = token.partition("=")
            if key == "kind_named":
                allowed = prod_pod_sanitizer._RECOGNIZED_KINDS | {"<UNRECOGNIZED>"}
                self.assertIn(value, allowed, f"kind_named had unexpected value: {value!r}")
                continue
            self.assertIn(key, self._ALLOWED_VALUE_PATTERN_BY_KEY, f"unexpected diagnostic key: {key!r}")
            pattern = self._ALLOWED_VALUE_PATTERN_BY_KEY[key]
            self.assertRegex(value, rf"^(?:{pattern})$", f"{key}={value!r} not in allowed vocabulary")

    def test_h_unexpected_shape_diagnostic_tokens_are_all_well_formed(self):
        raw = json.dumps({"kind": "SneakyKindValueXYZ", "items": [1, 2, 3]})
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json(raw)
        for line in cm.output:
            self._assert_all_tokens_well_formed(line)

    def test_h_malformed_diagnostic_tokens_are_all_well_formed(self):
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json("{sneaky malformed payload data")
        for line in cm.output:
            self._assert_all_tokens_well_formed(line)

    def test_h_recognized_kind_diagnostic_tokens_are_all_well_formed(self):
        with self.assertLogs(self._LOGGER_NAME, level="WARNING") as cm:
            prod_pod_sanitizer.sanitize_pod_list_json(json.dumps({"kind": "Deployment"}))
        for line in cm.output:
            self._assert_all_tokens_well_formed(line)


if __name__ == "__main__":
    unittest.main()
