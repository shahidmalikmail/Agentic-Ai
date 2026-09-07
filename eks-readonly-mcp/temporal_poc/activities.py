from temporalio import activity


@activity.defn
async def hello_activity(name: str) -> str:
    return f"Hello, {name}! Temporal POC is working."
