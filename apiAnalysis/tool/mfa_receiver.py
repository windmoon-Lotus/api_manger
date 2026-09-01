"""Short-lived MFA receiver primitives for authentication Recipes.

The default broker keeps verification codes in process memory. When an
explicit Redis URL is configured, Web and worker processes share encrypted,
TTL-bounded transactions instead. Both modes consume each code at most once.
"""
from __future__ import annotations

import datetime as dt
import base64
import hashlib
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_RECEIVER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
MAX_MFA_WAIT_SECONDS = 300
MAX_MFA_CODE_LENGTH = 256
MAX_PENDING_TRANSACTIONS = 100


class MfaReceiverError(RuntimeError):
    """Safe receiver failure that never contains a verification code."""


class MfaReceiverTimeout(MfaReceiverError):
    pass


def normalize_receiver_id(value: str) -> str:
    receiver_id = str(value or "").strip()
    if not _RECEIVER_ID.fullmatch(receiver_id):
        raise ValueError("MFA receiver id is invalid")
    return receiver_id


def validate_mfa_code(value: object) -> str:
    code = str(value or "").strip()
    if (
            not code
            or len(code) > MAX_MFA_CODE_LENGTH
            or any(ord(char) < 32 or ord(char) == 127 for char in code)):
        raise ValueError("MFA verification code is invalid")
    return code


@dataclass
class _PendingTransaction:
    transaction_id: str
    receiver_id: str
    correlation: str
    created_at: float
    expires_at: float
    code: Optional[str] = None


class MfaPushBroker:
    """Thread-safe, single-process, one-time MFA push inbox."""

    def __init__(self, *, max_pending: int = MAX_PENDING_TRANSACTIONS):
        self.max_pending = max(1, min(int(max_pending), MAX_PENDING_TRANSACTIONS))
        self._condition = threading.Condition()
        self._pending: Dict[str, _PendingTransaction] = {}

    def _cleanup_locked(self, now: Optional[float] = None) -> None:
        current = time.time() if now is None else float(now)
        expired = [
            transaction_id
            for transaction_id, item in self._pending.items()
            if item.expires_at <= current
        ]
        for transaction_id in expired:
            self._pending.pop(transaction_id, None)

    def wait(self, receiver_id: str, *, correlation: str = "",
             timeout_seconds: int = 60) -> str:
        receiver_id = normalize_receiver_id(receiver_id)
        correlation = str(correlation or "").strip()[:256]
        timeout_seconds = max(1, min(int(timeout_seconds), MAX_MFA_WAIT_SECONDS))
        now = time.time()
        transaction = _PendingTransaction(
            transaction_id="mfa-{}".format(secrets.token_urlsafe(24)),
            receiver_id=receiver_id,
            correlation=correlation,
            created_at=now,
            expires_at=now + timeout_seconds,
        )
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            self._cleanup_locked(now)
            if len(self._pending) >= self.max_pending:
                raise MfaReceiverError("MFA receiver queue is full")
            self._pending[transaction.transaction_id] = transaction
            self._condition.notify_all()
            while transaction.code is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._pending.pop(transaction.transaction_id, None)
                    raise MfaReceiverTimeout("MFA receiver timed out")
                self._condition.wait(timeout=min(remaining, 1.0))
            code = transaction.code
            self._pending.pop(transaction.transaction_id, None)
        return validate_mfa_code(code)

    def deliver(self, transaction_id: str, code: object) -> bool:
        transaction_id = str(transaction_id or "").strip()
        code = validate_mfa_code(code)
        with self._condition:
            self._cleanup_locked()
            transaction = self._pending.get(transaction_id)
            if transaction is None or transaction.code is not None:
                return False
            transaction.code = code
            self._condition.notify_all()
            return True

    def pending(self, receiver_id: str = "") -> List[Dict[str, object]]:
        selected_receiver = (
            normalize_receiver_id(receiver_id) if str(receiver_id or "").strip() else ""
        )
        with self._condition:
            self._cleanup_locked()
            rows = [
                item for item in self._pending.values()
                if not selected_receiver or item.receiver_id == selected_receiver
            ]
            rows.sort(key=lambda item: item.created_at)
            return [
                {
                    "transaction_id": item.transaction_id,
                    "receiver_id": item.receiver_id,
                    "correlation": item.correlation,
                    "created_at": dt.datetime.utcfromtimestamp(
                        item.created_at,
                    ).isoformat() + "Z",
                    "expires_at": dt.datetime.utcfromtimestamp(
                        item.expires_at,
                    ).isoformat() + "Z",
                }
                for item in rows[:MAX_PENDING_TRANSACTIONS]
            ]

    def clear(self) -> None:
        """Drop pending transactions; intended for orderly shutdown and tests."""
        with self._condition:
            self._pending.clear()
            self._condition.notify_all()


_DEFAULT_PUSH_BROKER = MfaPushBroker()
_REDIS_BROKERS: Dict[str, "RedisMfaPushBroker"] = {}
_REDIS_BROKERS_LOCK = threading.Lock()


def _receiver_api_token() -> str:
    return str(os.getenv("API_MANAGER_MFA_RECEIVER_TOKEN", "")).strip()


def _encryption_key() -> bytes:
    token = _receiver_api_token()
    if len(token) < 16:
        raise MfaReceiverError("MFA receiver token is unavailable or too short")
    return hashlib.sha256(
        b"api-manager-mfa-receiver-v1\x00" + token.encode("utf-8"),
    ).digest()


def _encrypt_code(transaction_id: str, code: str) -> str:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(_encryption_key()).encrypt(
        nonce, validate_mfa_code(code).encode("utf-8"),
        str(transaction_id).encode("utf-8"),
    )
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def _decrypt_code(transaction_id: str, payload: str) -> str:
    try:
        decoded = base64.b64decode(str(payload or ""), validate=True)
        plaintext = AESGCM(_encryption_key()).decrypt(
            decoded[:12], decoded[12:], str(transaction_id).encode("utf-8"),
        )
    except Exception:
        raise MfaReceiverError("MFA receiver payload could not be decrypted") from None
    return validate_mfa_code(plaintext.decode("utf-8"))


class RedisMfaPushBroker:
    """Cross-process MFA inbox with encrypted, TTL-bounded Redis values."""

    _PREFIX = "api-manager:mfa-receiver:v1"

    def __init__(self, redis_url: str):
        redis_url = str(redis_url or "").strip()
        if not redis_url:
            raise ValueError("MFA receiver Redis URL is required")
        try:
            import redis
            self.client = redis.Redis.from_url(
                redis_url, decode_responses=True,
                socket_connect_timeout=3, socket_timeout=3,
            )
        except Exception:
            raise MfaReceiverError("MFA receiver Redis client is unavailable") from None
        # Fail configuration early instead of publishing an unusable transaction.
        _encryption_key()

    @classmethod
    def _transaction_key(cls, transaction_id: str) -> str:
        return "{}:transaction:{}".format(cls._PREFIX, transaction_id)

    @classmethod
    def _pending_key(cls, receiver_id: str) -> str:
        return "{}:pending:{}".format(cls._PREFIX, receiver_id)

    def wait(self, receiver_id: str, *, correlation: str = "",
             timeout_seconds: int = 60) -> str:
        receiver_id = normalize_receiver_id(receiver_id)
        correlation = str(correlation or "").strip()[:256]
        timeout_seconds = max(1, min(int(timeout_seconds), MAX_MFA_WAIT_SECONDS))
        transaction_id = "mfa-{}".format(secrets.token_urlsafe(24))
        transaction_key = self._transaction_key(transaction_id)
        pending_key = self._pending_key(receiver_id)
        now = time.time()
        expires_at = now + timeout_seconds
        try:
            pipeline = self.client.pipeline(transaction=True)
            transaction_fields = {
                "transaction_id": transaction_id,
                "receiver_id": receiver_id,
                "correlation": correlation,
                "created_at": repr(now),
                "expires_at": repr(expires_at),
            }
            # Redis 3 only supports one field/value pair per HSET command.
            for field, value in transaction_fields.items():
                pipeline.hset(transaction_key, field, value)
            pipeline.expire(transaction_key, timeout_seconds + 5)
            pipeline.zadd(pending_key, {transaction_id: expires_at})
            pipeline.expire(pending_key, timeout_seconds + 10)
            pipeline.execute()
        except Exception:
            raise MfaReceiverError("MFA receiver Redis write failed") from None

        deadline = time.monotonic() + timeout_seconds
        try:
            while time.monotonic() < deadline:
                try:
                    payload = self.client.hget(transaction_key, "code")
                except Exception:
                    raise MfaReceiverError("MFA receiver Redis read failed") from None
                if payload:
                    return _decrypt_code(transaction_id, payload)
                time.sleep(0.2)
            raise MfaReceiverTimeout("MFA receiver timed out")
        finally:
            try:
                pipeline = self.client.pipeline(transaction=True)
                pipeline.delete(transaction_key)
                pipeline.zrem(pending_key, transaction_id)
                pipeline.execute()
            except Exception:
                pass

    def deliver(self, transaction_id: str, code: object) -> bool:
        transaction_id = str(transaction_id or "").strip()
        if not transaction_id.startswith("mfa-") or len(transaction_id) > 128:
            return False
        payload = _encrypt_code(transaction_id, validate_mfa_code(code))
        script = """
        if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
        if redis.call('HEXISTS', KEYS[1], 'code') == 1 then return 0 end
        redis.call('HSET', KEYS[1], 'code', ARGV[1])
        return 1
        """
        try:
            return int(self.client.eval(
                script, 1, self._transaction_key(transaction_id), payload,
            )) == 1
        except Exception:
            raise MfaReceiverError("MFA receiver Redis delivery failed") from None

    def pending(self, receiver_id: str = "") -> List[Dict[str, object]]:
        selected_receiver = (
            normalize_receiver_id(receiver_id) if str(receiver_id or "").strip() else ""
        )
        if not selected_receiver:
            return []
        pending_key = self._pending_key(selected_receiver)
        now = time.time()
        try:
            self.client.zremrangebyscore(pending_key, "-inf", now)
            transaction_ids = self.client.zrangebyscore(
                pending_key, now, "+inf", start=0, num=MAX_PENDING_TRANSACTIONS,
            )
            pipeline = self.client.pipeline(transaction=False)
            for transaction_id in transaction_ids:
                pipeline.hgetall(self._transaction_key(transaction_id))
            records = pipeline.execute() if transaction_ids else []
        except Exception:
            raise MfaReceiverError("MFA receiver Redis read failed") from None
        result: List[Dict[str, object]] = []
        for transaction_id, record in zip(transaction_ids, records):
            if not record or record.get("code"):
                continue
            try:
                created_at = float(record.get("created_at") or 0)
                expires_at = float(record.get("expires_at") or 0)
            except (TypeError, ValueError):
                continue
            result.append({
                "transaction_id": transaction_id,
                "receiver_id": selected_receiver,
                "correlation": str(record.get("correlation") or "")[:256],
                "created_at": dt.datetime.utcfromtimestamp(
                    created_at,
                ).isoformat() + "Z",
                "expires_at": dt.datetime.utcfromtimestamp(
                    expires_at,
                ).isoformat() + "Z",
            })
        return result

    def clear(self) -> None:
        """Remove only this broker's namespaced short-lived keys."""
        try:
            keys = list(self.client.scan_iter(match="{}:*".format(self._PREFIX), count=100))
            if keys:
                self.client.delete(*keys)
        except Exception:
            pass


def default_mfa_push_broker():
    redis_url = str(os.getenv("API_MANAGER_MFA_RECEIVER_REDIS_URL", "")).strip()
    if not redis_url:
        return _DEFAULT_PUSH_BROKER
    with _REDIS_BROKERS_LOCK:
        broker = _REDIS_BROKERS.get(redis_url)
        if broker is None:
            broker = RedisMfaPushBroker(redis_url)
            _REDIS_BROKERS[redis_url] = broker
        return broker
