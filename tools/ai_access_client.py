"""Compatibility entry point for the standalone authcheck CLI."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'clients' / 'authcheck_cli'))
from authcheck_cli.client import Client, ClientError, NoRedirect, doctor
from authcheck_cli.cli import main

if __name__ == '__main__':
    raise SystemExit(main())
