import asyncio
import structlog

logger = structlog.get_logger()

async def run_worker():
    logger.info("Worker started")
    while True:
        await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(run_worker())
