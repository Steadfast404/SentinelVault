import redis.asyncio as redis
from app.core.config import settings

redis_pool = redis.ConnectionPool.from_url(settings.redis_url, decode_responses=True)

async def get_redis():
    client = redis.Redis(connection_pool=redis_pool)
    try:
        yield client
    finally:
        await client.close()

async def check_redis_health() -> bool:
    try:
        client = redis.Redis(connection_pool=redis_pool)
        await client.ping()
        await client.close()
        return True
    except Exception:
        return False
