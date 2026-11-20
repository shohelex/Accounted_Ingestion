import logging
from typing import Optional
import redis.asyncio as redis
from redis.asyncio import Redis

from config import settings

logger = logging.getLogger(__name__)

class CacheManager:
    def __init__(self):
        self.redis_client: Optional[Redis] = None

    async def initialize(self):
        try:
            self.redis_client = redis.from_url(
                settings.redis_url,
                db=settings.redis_db,
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30
            )
            await self.redis_client.ping()
            logger.info("Cache manager initialized")

        except Exception as e:
            logger.error(f"Failed to initialize cache manager: {e}")
            raise

    async def close(self):
        if self.redis_client:
            await self.redis_client.close()

cache_manager = CacheManager()
