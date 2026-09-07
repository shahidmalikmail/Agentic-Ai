import asyncio

from temporalio.client import Client
from temporalio.worker import Worker

from temporal_poc.eks_activities import collect_cluster_info, collect_pod_state
from temporal_poc.eks_workflow import EKSReadOnlyHealthWorkflow

TEMPORAL_ADDRESS = "localhost:7233"
TEMPORAL_NAMESPACE = "default"
TASK_QUEUE = "hcl-ai-eks-readonly-poc"


async def main() -> None:
    client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)

    worker = Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[EKSReadOnlyHealthWorkflow],
        activities=[collect_cluster_info, collect_pod_state],
    )

    print(f"Starting EKS read-only POC worker on task queue '{TASK_QUEUE}'...")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
