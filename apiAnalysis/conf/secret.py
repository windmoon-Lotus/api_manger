import os
import secrets


def _env(name, default=None):
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name, default):
    value = _env(name)
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _env_bytes(name, default):
    value = _env(name)
    if value is None:
        return default
    return value.encode("utf-8")

# flask app. Without an explicit key, use an ephemeral process-local key rather
# than a repository-wide constant. Set API_MANAGER_SECRET_KEY to keep sessions
# valid across restarts.
_configured_secret_key = _env_bytes("API_MANAGER_SECRET_KEY", None)
secret_key_is_ephemeral = _configured_secret_key is None
secret_key = _configured_secret_key or secrets.token_bytes(32)

# mongodb
mongo_database = _env("API_MANAGER_MONGO_DATABASE", "apihandl")
mongo_host = _env("API_MANAGER_MONGO_HOST", "127.0.0.1")
mongo_port = _env_int("API_MANAGER_MONGO_PORT", 27017)
mongo_user = _env("API_MANAGER_MONGO_USER", "")
mongo_password = _env("API_MANAGER_MONGO_PASSWORD", "")


# redis
redis_host = _env("API_MANAGER_REDIS_HOST", "127.0.0.1")
redis_port = _env_int("API_MANAGER_REDIS_PORT", 6379)
redis_db = _env_int("API_MANAGER_REDIS_DB", 0)
redis_password = _env("API_MANAGER_REDIS_PASSWORD", "")
