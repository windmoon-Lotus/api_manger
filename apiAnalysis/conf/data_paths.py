"""Owned paths for private runtime data.

The public source tree must never be the default destination for credentials,
uploaded interface descriptions, raw request/response bodies, browser captures
or evidence.  This module keeps that invariant in one place so callers do not
re-create repository-relative paths.
"""

import hashlib
import os
from pathlib import Path


DATA_DIR_ENV = "API_MANAGER_DATA_DIR"
ALLOW_UNSAFE_DATA_DIR_ENV = "API_MANAGER_ALLOW_UNSAFE_DATA_DIR"

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LEGACY_PRIVATE_ROOT = REPOSITORY_ROOT.parent / ".secrets"


def _is_within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _platform_private_root():
    """Return a per-user private root for a fresh installation."""
    if os.name == "nt":
        local_app_data = os.getenv("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "AuthCheck" / "data"
    xdg_data_home = os.getenv("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home).expanduser() / "authcheck"
    return Path.home() / ".local" / "share" / "authcheck"


def private_data_root(create=False):
    """Resolve the private data root and reject repository-local storage.

    Existing installations keep using the sibling ``.secrets`` directory when
    it already exists.  A configured ``API_MANAGER_DATA_DIR`` always wins.
    ``API_MANAGER_ALLOW_UNSAFE_DATA_DIR=1`` is a temporary migration escape
    hatch and must not be used for a governed public baseline.
    """
    configured = str(os.getenv(DATA_DIR_ENV) or "").strip()
    if configured:
        root = Path(configured).expanduser()
    elif LEGACY_PRIVATE_ROOT.exists():
        root = LEGACY_PRIVATE_ROOT
    else:
        root = _platform_private_root()

    root = root.resolve()
    repository_root = REPOSITORY_ROOT.resolve()
    if _is_within(root, repository_root):
        if os.getenv(ALLOW_UNSAFE_DATA_DIR_ENV, "0") != "1":
            raise RuntimeError(
                "private data directory must be outside the Git repository: {}".format(root)
            )
    if create:
        root.mkdir(parents=True, exist_ok=True)
    return root


def private_data_path(*parts, **kwargs):
    create_parent = bool(kwargs.pop("create_parent", False))
    if kwargs:
        raise TypeError("unsupported keyword arguments: {}".format(", ".join(kwargs)))
    path = private_data_root(create=create_parent).joinpath(*parts)
    if create_parent:
        path.parent.mkdir(parents=True, exist_ok=True)
    return path


def private_upload_dir(create=False):
    path = private_data_root(create=create) / "uploads"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def private_evidence_dir(create=False):
    path = private_data_root(create=create) / "evidence"
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def is_repository_local(path):
    return _is_within(Path(path).expanduser().resolve(), REPOSITORY_ROOT.resolve())


def public_private_reference(value):
    """Return a non-reversible public reference for a local private path."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("private://sha256/"):
        return raw
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    return "private://sha256/{}".format(digest)
