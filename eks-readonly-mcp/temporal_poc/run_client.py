import asyncio
import uuid

from temporalio.client import Client

from temporal_poc.workflow import HelloTemporalWorkflow

TEMPORAL_ADDRESS = "localhost:7233"
TEMPORAL_NAMESPACE = "default"
TASK_QUEUE = "hcl-ai-temporal-poc"


async def main() -> None:
    client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)

    workflow_id = f"hello-temporal-poc-{uuid.uuid4()}"

    handle = await client.start_workflow(
        HelloTemporalWorkflow.run,
        "Shahid",
        id=workflow_id,
        task_queue=TASK_QUEUE,
    )

    print(f"Workflow ID: {handle.id}")
    print(f"Run ID: {handle.result_run_id}")

    result = await handle.result()
    print(f"Result: {result}")


if __name__ == "__main__":
    asyncio.run(main())
