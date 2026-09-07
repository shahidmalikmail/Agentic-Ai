import asyncio
import json
import unittest
from unittest.mock import patch

import temporal_poc.eks_activities as eks_activities


def _pods_payload(count: int) -> str:
    items = [
        {
            "metadata": {"namespace": "commerce", "name": f"pod-{i}"},
            "status": {
                "phase": "Running",
                "containerStatuses": [{"ready": True, "restartCount": 0}],
            },
        }
        for i in range(count)
    ]
    return "[env=uat]\n" + json.dumps({"items": items})


class TestActivityAndWorkflowImports(unittest.TestCase):
    def test_eks_activities_import_successfully(self):
        from temporal_poc.eks_activities import collect_cluster_info, collect_pod_state

        self.assertTrue(callable(collect_cluster_info))
        self.assertTrue(callable(collect_pod_state))

    def test_eks_workflow_imports_successfully(self):
        from temporal_poc.eks_workflow import EKSReadOnlyHealthWorkflow

        self.assertIsNotNone(EKSReadOnlyHealthWorkflow)


class TestEnvironmentValidation(unittest.TestCase):
    def test_uat_is_accepted(self):
        self.assertEqual(eks_activities._validate_environment("uat"), "uat")

    def test_dev_is_rejected(self):
        with self.assertRaises(ValueError):
            eks_activities._validate_environment("dev")

    def test_prod_is_rejected(self):
        with self.assertRaises(ValueError):
            eks_activities._validate_environment("prod")

    def test_collect_cluster_info_rejects_non_uat_without_calling_run(self):
        with patch.object(eks_activities, "_run") as mock_run:
            with self.assertRaises(ValueError):
                asyncio.run(eks_activities.collect_cluster_info("dev"))
            mock_run.assert_not_called()

    def test_collect_pod_state_rejects_non_uat_without_calling_run(self):
        with patch.object(eks_activities, "_run") as mock_run:
            with self.assertRaises(ValueError):
                asyncio.run(eks_activities.collect_pod_state("prod"))
            mock_run.assert_not_called()


class TestCollectClusterInfo(unittest.TestCase):
    def test_success_returns_bounded_lines(self):
        raw = "[env=uat]\nKubernetes control plane is running at https://example\n"
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_cluster_info("uat"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["environment"], "uat")
        self.assertIn("Kubernetes control plane is running at https://example", result["cluster_info_lines"])
        self.assertIsNone(result["error"])

    def test_error_result_is_reported_not_raised(self):
        raw = "[env=uat] Error: could not connect to the bastion."
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_cluster_info("uat"))

        self.assertFalse(result["ok"])
        self.assertIn("could not connect", result["error"])
        self.assertEqual(result["cluster_info_lines"], [])


class TestCollectPodState(unittest.TestCase):
    def test_bounded_to_max_pods_returned(self):
        raw = _pods_payload(eks_activities._MAX_PODS_RETURNED + 25)
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_pod_state("uat"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["total_pods"], eks_activities._MAX_PODS_RETURNED + 25)
        self.assertEqual(result["pods_returned"], eks_activities._MAX_PODS_RETURNED)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["pods"]), eks_activities._MAX_PODS_RETURNED)

    def test_small_pod_list_is_not_marked_truncated(self):
        raw = _pods_payload(3)
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_pod_state("uat"))

        self.assertTrue(result["ok"])
        self.assertEqual(result["total_pods"], 3)
        self.assertEqual(result["pods_returned"], 3)
        self.assertFalse(result["truncated"])

    def test_pod_summary_has_no_raw_manifest_fields(self):
        raw = _pods_payload(1)
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_pod_state("uat"))

        pod = result["pods"][0]
        self.assertEqual(
            set(pod.keys()),
            {"namespace", "name", "phase", "ready", "restart_count", "waiting_reason"},
        )

    def test_error_result_is_reported_not_raised(self):
        raw = "[env=uat] Error: kubectl failed (exit 1): forbidden"
        with patch.object(eks_activities, "_run", return_value=raw):
            result = asyncio.run(eks_activities.collect_pod_state("uat"))

        self.assertFalse(result["ok"])
        self.assertEqual(result["pods"], [])
        self.assertIn("forbidden", result["error"])


if __name__ == "__main__":
    unittest.main()
