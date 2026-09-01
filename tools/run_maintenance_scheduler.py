"""Run periodic recovery in a process separate from Web and workers."""
import argparse
import json
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apscheduler.schedulers.blocking import BlockingScheduler

from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.maintenance import run_maintenance_once


def main():
    parser = argparse.ArgumentParser(description="Run API Manager maintenance recovery jobs.")
    parser.add_argument("--once", action="store_true", help="Run recovery once and exit.")
    parser.add_argument("--interval-seconds", type=int, default=60)
    parser.add_argument("--queue-name", default="snapshot")
    args = parser.parse_args()
    if not 15 <= int(args.interval_seconds) <= 86400:
        parser.error("--interval-seconds must be between 15 and 86400")

    _ensure_mongo_connection()
    if args.once:
        print(json.dumps(run_maintenance_once(args.queue_name), sort_keys=True))
        return

    scheduler = BlockingScheduler()
    scheduler.add_job(
        run_maintenance_once,
        "interval",
        seconds=int(args.interval_seconds),
        kwargs={"queue_name": args.queue_name},
        id="durable-run-recovery",
        max_instances=1,
        coalesce=True,
    )

    def stop_scheduler(*_):
        if scheduler.running:
            scheduler.shutdown(wait=False)

    signal.signal(signal.SIGINT, stop_scheduler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop_scheduler)
    # Recover immediately, then continue on the configured interval.
    run_maintenance_once(args.queue_name)
    scheduler.start()


if __name__ == "__main__":
    main()
