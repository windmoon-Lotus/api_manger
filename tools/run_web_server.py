"""Run only the Flask Web process; workers and schedulers are separate CLIs."""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from local_web_credentials import bootstrap_local_web_credentials

bootstrap_local_web_credentials()

from apiAnalysis import create_app


def main():
    app = create_app()
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
