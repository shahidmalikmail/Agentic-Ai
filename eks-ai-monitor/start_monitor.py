"""Creates (or reuses) a Temporal Schedule that runs EKSMonitoringWorkflow
on a configurable interval, and triggers one immediate run.

Each scheduled run is its own workflow execution with its own result,
visible in the local Temporal Web UI under Schedules / Workflows.

Run with: python start_monitor.py
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta

from dotenv import load_dotenv
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleAlreadyRunningError,
    ScheduleIntervalSpec,
    ScheduleSpec,
)

from app.config import load_config
from app.workflows import EKSMonitoringWorkflow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

SCHEDULE_ID = "eks-monitoring-schedule"
WORKFLOW_ID = "eks-monitoring-workflow"


async def main() -> None:
    load_dotenv()
    config = load_config()

    client = await Client.connect(config.temporal.host, namespace=config.temporal.namespace)

    schedule = Schedule(
        action=ScheduleActionStartWorkflow(
            EKSMonitoringWorkflow.run,
            id=WORKFLOW_ID,
            task_queue=config.temporal.task_queue,
            execution_timeout=timedelta(minutes=15),
        ),
        spec=ScheduleSpec(
            intervals=[ScheduleIntervalSpec(every=timedelta(seconds=config.monitor.interval_seconds))]
        ),
    )

    try:
        handle = await client.create_schedule(SCHEDULE_ID, schedule, trigger_immediately=True)
        logger.info(
            f"[TEMPORAL] Created schedule '{SCHEDULE_ID}' "
            f"(every {config.monitor.interval_seconds}s) and triggered an immediate run"
        )
    except ScheduleAlreadyRunningError:
        handle = client.get_schedule_handle(SCHEDULE_ID)
        await handle.trigger()
        logger.info(
            f"[TEMPORAL] Schedule '{SCHEDULE_ID}' already exists - triggered an immediate run. "
            "To change the interval, delete the schedule first "
            f"(temporal schedule delete --schedule-id {SCHEDULE_ID}) and re-run this script."
        )

    logger.info("Open the Temporal Web UI (usually http://localhost:8233) to watch workflow runs and results.")


if __name__ == "__main__":
    asyncio.run(main())
