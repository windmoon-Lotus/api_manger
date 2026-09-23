"""Hashed account credentials, optional project limits and call metadata."""
import datetime as dt
from mongoengine import Document, StringField, DateTimeField, BooleanField, IntField, DictField


class AiAccessKey(Document):
    name = StringField(required=True, max_length=120)
    owner = StringField(required=True)
    digest = StringField(required=True, unique=True)
    prefix = StringField(required=True)
    project_id = StringField(default='')  # Optional narrowing; empty inherits account scope.
    mode = StringField(required=True, choices=['read_only', 'account'])
    active = BooleanField(default=True)
    expires_at = DateTimeField(required=True)
    created_at = DateTimeField(default=dt.datetime.utcnow)
    last_used_at = DateTimeField()
    meta = {'collection': 'ai_access_key', 'indexes': ['owner']}


class AiAccessCall(Document):
    request_id = StringField(required=True, unique=True)
    key_id = StringField(required=True)
    owner = StringField(required=True)
    tool = StringField(required=True)
    fingerprint = StringField()
    state = StringField(default='pending')
    status = IntField(default=202)
    elapsed_ms = IntField(default=0)
    error = StringField(default='')
    receipt = DictField()  # Only execution IDs, never arguments or tool bodies.
    subject = DictField()  # Project/plan references for safe retry correlation.
    created_at = DateTimeField(default=dt.datetime.utcnow)
    meta = {'collection': 'ai_access_call', 'indexes': ['key_id', 'owner', '-created_at']}
