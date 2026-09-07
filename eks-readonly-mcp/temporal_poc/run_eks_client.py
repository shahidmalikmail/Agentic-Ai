import asyncio
import json
import uuid

from temporalio.client import Client

from temporal_poc.eks_workflow import EKSReadOnlyHealthWorkflow

TEMPORAL_ADDRESS = "localhost:7233"
TEMPORAL_NAMESPACE = "default"
TASK_QUEUE = "hcl-ai-eks-readonly-poc"
ENVIRONMENT = "uat"


async def main() -> None:
    client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)

    workflow_id = f"eks-readonly-health-{ENVIRONMENT}-{uuid.uuid4()}"

    handle = await client.start_workflow(
        EKSReadOnlyHealthWorkflow.run,
        ENVIRONMENT,
        id=workflow_id,
        task_queue=TASK_QUEUE,
    )

    print(f"Workflow ID: {handle.id}")
    print(f"Run ID: {handle.result_run_id}")

    result = await handle.result()
    print("Result:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
