"""Run the durable parameter-relation analysis worker as its own process."""
import argparse
import json
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool.parameter_analysis import ParameterRelationAnalysisWorker


def main():
    parser = argparse.ArgumentParser(description="Run Mongo-backed relation analysis jobs.")
    parser.add_argument("--once", action="store_true", help="Claim at most one job and exit.")
    parser.add_argument("--recover-only", action="store_true", help="Requeue abandoned jobs and exit.")
    parser.add_argument("--worker-id", default="")
    parser.add_argument("--lease-seconds", type=int, default=60)
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()

    _ensure_mongo_connection()
    worker = ParameterRelationAnalysisWorker(
        worker_id=args.worker_id,
        poll_seconds=args.poll_seconds,
        lease_seconds=args.lease_seconds,
    )
    recovered = worker.recover_abandoned()
    if args.recover_only:
        print(json.dumps({"requeued": recovered}, sort_keys=True))
        return

    def stop_worker(*_):
        worker.stop()

    signal.signal(signal.SIGINT, stop_worker)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_worker)
    if args.once:
        print(json.dumps({"result": worker.run_once(), "requeued": recovered}, sort_keys=True))
        return
    worker.run_forever()


if __name__ == "__main__":
    main()
