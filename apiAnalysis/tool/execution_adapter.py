"""Typed worker adapter contracts for snapshot execution workflows."""
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, Iterable, Optional


class ExecutionAdapterError(RuntimeError):
    pass


class UnsupportedExecutionAdapter(ExecutionAdapterError):
    pass


class UnsupportedExecutionAdapterVersion(ExecutionAdapterError):
    pass


class ExecutionAdapterAuthModeMismatch(ExecutionAdapterError):
    pass


class ExecutionAdapterMutationMismatch(ExecutionAdapterError):
    pass


class ExecutionRequestBlocked(ExecutionAdapterError):
    def __init__(self, reason: str):
        self.reason = str(reason or "request_blocked")
        super().__init__(self.reason)


REQUEST_POLICY_SCOPES = frozenset({"checkpoint", "request"})


@dataclass(frozen=True)
class ExecutionAdapter:
    adapter_id: str
    adapter_version: str
    replay: Callable[..., Dict[str, Any]]
    judge: Callable[..., Any]
    auth_modes: FrozenSet[str]
    requires_account_context: bool = False
    supports_mutation: bool = False
    request_policy_scope: str = "checkpoint"
    record: Optional[Callable[..., Any]] = None

    def validate(self, run: Any, allow_mutation: bool = False) -> None:
        if str(getattr(run, "adapter_id", "") or "") != self.adapter_id:
            raise UnsupportedExecutionAdapter("execution adapter is not registered")
        if str(getattr(run, "adapter_version", "") or "1") != self.adapter_version:
            raise UnsupportedExecutionAdapterVersion("execution adapter version is not supported")
        auth_mode = str(getattr(run, "auth_mode", "") or "inherit")
        if auth_mode not in self.auth_modes:
            raise ExecutionAdapterAuthModeMismatch("execution adapter does not support auth_mode")
        if allow_mutation and not self.supports_mutation:
            raise ExecutionAdapterMutationMismatch("execution adapter does not support mutations")


def builtin_execution_adapters(replay: Callable[..., Dict[str, Any]],
                               judge: Callable[..., Any]) -> Dict[str, ExecutionAdapter]:
    adapters = (
        ExecutionAdapter(
            adapter_id="snapshot_batch",
            adapter_version="1",
            replay=replay,
            judge=judge,
            auth_modes=frozenset({"anonymous", "inherit"}),
            requires_account_context=False,
            supports_mutation=False,
        ),
        ExecutionAdapter(
            adapter_id="authenticated_snapshot_batch",
            adapter_version="1",
            replay=replay,
            judge=judge,
            auth_modes=frozenset({"account"}),
            requires_account_context=True,
            supports_mutation=False,
        ),
    )
    return {adapter.adapter_id: adapter for adapter in adapters}


def adapter_registry(adapters: Iterable[ExecutionAdapter]) -> Dict[str, ExecutionAdapter]:
    result: Dict[str, ExecutionAdapter] = {}
    for adapter in adapters:
        if (
            not adapter.adapter_id or not adapter.adapter_version
            or not callable(adapter.replay) or not callable(adapter.judge)
        ):
            raise ValueError("execution adapter id, version, replay and judge are required")
        if not adapter.auth_modes or not set(adapter.auth_modes).issubset({
            "anonymous", "account", "inherit", "matrix",
        }):
            raise ValueError("execution adapter auth_modes are invalid")
        if ("account" in adapter.auth_modes) != bool(adapter.requires_account_context):
            raise ValueError("account adapters must require AccountContext")
        if adapter.request_policy_scope not in REQUEST_POLICY_SCOPES:
            raise ValueError("execution adapter request_policy_scope is invalid")
        if adapter.record is not None and not callable(adapter.record):
            raise ValueError("execution adapter record hook must be callable")
        if adapter.adapter_id in result:
            raise ValueError("duplicate execution adapter id")
        result[adapter.adapter_id] = adapter
    return result
