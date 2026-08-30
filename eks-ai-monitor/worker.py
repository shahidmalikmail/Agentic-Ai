"""Temporal worker process.

Connects to a LOCAL Temporal server (never the bastion) and polls the
configured task queue for EKSMonitoringWorkflow executions and its
activities. Activities are synchronous (paramiko + anthropic are
blocking), so they run on a ThreadPoolExecutor via `activity_executor`.

Run with: python worker.py
"""
from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from dotenv import load_dotenv
from temporalio.client import Client
from temporalio.worker import Worker

from app.activities import analyze_cluster_data, check_bastion_connection, collect_cluster_data
from app.config import load_config
from app.workflows import EKSMonitoringWorkflow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


async def main() -> None:
    load_dotenv()
    config = load_config()

    logger.info(f"[TEMPORAL] Connecting to Temporal server at {config.temporal.host}")
    client = await Client.connect(config.temporal.host, namespace=config.temporal.namespace)

    with ThreadPoolExecutor(max_workers=10) as activity_executor:
        worker = Worker(
            client,
            task_queue=config.temporal.task_queue,
            workflows=[EKSMonitoringWorkflow],
            activities=[check_bastion_connection, collect_cluster_data, analyze_cluster_data],
            activity_executor=activity_executor,
        )
        logger.info(f"[TEMPORAL] Worker started on task queue '{config.temporal.task_queue}'")
        await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
