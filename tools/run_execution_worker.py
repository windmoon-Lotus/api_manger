"""Run the persistent execution worker; startup recovers expired leases."""
import argparse
import json
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.account_context import (
    AccountContextResolver,
    JsonFileAccountContextProvider,
    resolver_from_environment,
)
from apiAnalysis.tool.execution_scheduler import ExecutionWorker, recover_expired_executions


def main():
    parser = argparse.ArgumentParser(description="Run Mongo-backed snapshot execution jobs.")
    parser.add_argument("--once", action="store_true", help="Claim at most one queued run and exit.")
    parser.add_argument("--recover-only", action="store_true", help="Recover expired leases and exit.")
    parser.add_argument("--worker-id", default="")
    parser.add_argument("--queue-name", default="snapshot")
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--poll-seconds", type=int, default=5)
    parser.add_argument("--account-context-file", default="")
    parser.add_argument("--account-provider-id", default="local_json")
    parser.add_argument("--account-project-id", default="")
    parser.add_argument("--account-env-id", default="")
    parser.add_argument("--account-allowed-host", action="append", default=[])
    parser.add_argument("--account-context-max-age", type=int, default=1800)
    parser.add_argument("--account-context-cache-seconds", type=int, default=15)
    parser.add_argument(
        "--trace-requests", action="store_true",
        help="Print transient redacted request previews to stderr before network sends.",
    )
    args = parser.parse_args()
    _ensure_mongo_connection()
    recovered = recover_expired_executions(queue_name=args.queue_name)
    if args.recover_only:
        print(json.dumps(recovered, sort_keys=True))
        return
    if args.account_context_file:
        provider = JsonFileAccountContextProvider(
            args.account_context_file,
            provider_id=args.account_provider_id,
            default_project_id=args.account_project_id,
            default_env_id=args.account_env_id,
            allowed_hosts=args.account_allowed_host,
            max_age_seconds=args.account_context_max_age,
        )
        resolver = AccountContextResolver(
            [provider], cache_seconds=args.account_context_cache_seconds,
        )
    else:
        resolver = resolver_from_environment()
    trace_lock = threading.Lock()

    def print_request_trace(preview):
        with trace_lock:
            print(json.dumps(preview, ensure_ascii=False, sort_keys=True), file=sys.stderr, flush=True)

    worker = ExecutionWorker(
        worker_id=args.worker_id,
        queue_name=args.queue_name,
        lease_seconds=args.lease_seconds,
        account_context_resolver=resolver,
        request_trace_callback=print_request_trace if args.trace_requests else None,
    )

    def stop_worker(*_):
        worker.stop()

    signal.signal(signal.SIGINT, stop_worker)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_worker)
    if args.once:
        print(json.dumps({"claimed": worker.run_once(), "recovery": recovered}, sort_keys=True))
        return
    worker.run_forever(poll_seconds=args.poll_seconds)


if __name__ == "__main__":
    main()
