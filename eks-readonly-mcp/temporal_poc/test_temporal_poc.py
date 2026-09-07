import asyncio
import unittest


class TestTemporalImports(unittest.TestCase):
    def test_temporalio_imports_successfully(self):
        import temporalio  # noqa: F401
        from temporalio import activity, workflow  # noqa: F401
        from temporalio.client import Client  # noqa: F401
        from temporalio.worker import Worker  # noqa: F401

    def test_hello_temporal_workflow_imports_successfully(self):
        from temporal_poc.workflow import HelloTemporalWorkflow

        self.assertIsNotNone(HelloTemporalWorkflow)

    def test_hello_activity_returns_expected_result(self):
        from temporal_poc.activities import hello_activity

        result = asyncio.run(hello_activity("Shahid"))
        self.assertEqual(result, "Hello, Shahid! Temporal POC is working.")


if __name__ == "__main__":
    unittest.main()
