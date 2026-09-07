import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from temporal_poc.activities import hello_activity
from temporal_poc.workflow import HelloTemporalWorkflow

TEMPORAL_ADDRESS = "localhost:7233"
TEMPORAL_NAMESPACE = "default"
TASK_QUEUE = "hcl-ai-temporal-poc"


async def main() -> None:
    client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)

    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[HelloTemporalWorkflow],
        activities=[hello_activity],
    )

    print(f"Starting Temporal POC worker on task queue '{TASK_QUEUE}'...")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
