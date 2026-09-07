from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from temporal_poc.activities import hello_activity


@workflow.defn
class HelloTemporalWorkflow:
    @workflow.run
    async def run(self, name: str) -> str:
        return await workflow.execute_activity(
            hello_activity,
            name,
            start_to_close_timeout=timedelta(seconds=10),
        )
