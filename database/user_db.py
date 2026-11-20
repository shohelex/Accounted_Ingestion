import asyncio
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, Optional

from schemas import User, APIKey, UserRole

logger = logging.getLogger(__name__)


class UserDatabase:
    def __init__(self, storage_file: str = "database/users.json"):
        self.storage_file = storage_file
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, APIKey] = {}
        self._lock = asyncio.Lock()
        # last_used is written to disk at most this often
        self._last_used_flush_interval_s = 60.0
        self._last_used_flushed = 0.0
        self._load_data()
        self._bootstrap_from_env()

    def _bootstrap_from_env(self):
        """Seed one admin API key from BOOTSTRAP_API_KEY (keys shorter than 32 characters are
        ignored); only the key's SHA-256 is stored."""
        raw_key = (os.environ.get("BOOTSTRAP_API_KEY") or "").strip()
        if not raw_key:
            return
        if len(raw_key) < 32:
            logger.warning("BOOTSTRAP_API_KEY ignored: shorter than 32 characters")
            return

        hashed = hashlib.sha256(raw_key.encode()).hexdigest()
        env_sources = [s.strip() for s in (os.environ.get("BOOTSTRAP_API_KEY_SOURCES") or "").split(",")
                       if s.strip()] or None
        known = [k for k in self.api_keys.values() if k.hashed_key == hashed]
        if known:
            if env_sources is not None:
                for k in known:
                    k.sources = env_sources
            return

        tenant = os.environ.get("BOOTSTRAP_TENANT_ID", "default")
        user = User(user_id="bootstrap", tenant_id=tenant, role=UserRole.ADMIN)
        self.users[user.user_id] = user
        self.api_keys["bootstrap"] = APIKey(
            key_id="bootstrap",
            user_id=user.user_id,
            tenant_id=tenant,
            name="bootstrap",
            hashed_key=hashed,
            sources=env_sources,
        )
        logger.warning(f"BOOTSTRAP_API_KEY set: admin key seeded for tenant {tenant}")

    def _load_data(self):
        try:
            if os.path.exists(self.storage_file):
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    users_data = data.get('users', {})
                    api_keys_data = data.get('api_keys', {})

                    for user_id, user_dict in users_data.items():
                        try:
                            user_dict['created_at'] = datetime.fromisoformat(user_dict['created_at'])
                            self.users[user_id] = User(**user_dict)
                        except Exception as e:
                            logger.warning(f"Failed to load user {user_id}: {e}")

                    for key_id, key_dict in api_keys_data.items():
                        try:
                            key_dict['created_at'] = datetime.fromisoformat(key_dict['created_at'])
                            if key_dict.get('expires_at'):
                                key_dict['expires_at'] = datetime.fromisoformat(key_dict['expires_at'])
                            if key_dict.get('last_used'):
                                key_dict['last_used'] = datetime.fromisoformat(key_dict['last_used'])
                            self.api_keys[key_id] = APIKey(**key_dict)
                        except Exception as e:
                            logger.warning(f"Failed to load API key {key_id}: {e}")

        except Exception as e:
            logger.error(f"Failed to load user data: {e}")

    def _save_data(self):
        try:
            data = {
                'users': {uid: user.dict() for uid, user in self.users.items()},
                'api_keys': {kid: key.dict() for kid, key in self.api_keys.items()}
            }

            os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
            with open(self.storage_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        except Exception as e:
            logger.error(f"Failed to save user data: {e}")

    def _active_key(self, api_key: str) -> Optional[APIKey]:
        hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
        for key in self.api_keys.values():
            if key.hashed_key == hashed_key and key.is_active:
                if key.expires_at and datetime.utcnow() > key.expires_at:
                    continue
                return key
        return None

    async def get_user_by_api_key(self, api_key: str) -> Optional[User]:
        async with self._lock:
            key = self._active_key(api_key)
            if key is None:
                return None
            key.last_used = datetime.utcnow()
            now = time.monotonic()
            if now - self._last_used_flushed >= self._last_used_flush_interval_s:
                self._last_used_flushed = now
                self._save_data()
            return self.users.get(key.user_id)

    async def get_api_key_record(self, api_key: str) -> Optional[APIKey]:
        """The active, unexpired key record for a raw API key, or None. No side effects."""
        async with self._lock:
            return self._active_key(api_key)


user_db = UserDatabase()
