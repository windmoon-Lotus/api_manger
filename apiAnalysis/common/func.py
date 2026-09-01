"""Small presentation helpers used by the current Web application."""
import json
import time

from flask import session


def str_show(value):
    return "" if not value else str(value)


def format_json(data):
    if isinstance(data, str):
        data = json.loads(data)
    return json.dumps(data, indent=4, ensure_ascii=False)


def time_show(value):
    return time.ctime(value)


def time_now():
    return time.ctime()


def is_manager():
    from apiAnalysis.model.model import PolicyEnum

    return PolicyEnum.MANAGE.value in session.get("role", [])


__all__ = ["str_show", "format_json", "time_show", "time_now", "is_manager"]
