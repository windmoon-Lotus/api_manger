"""AI-only CLI protocol and soft policy (A0).

The CLI is a transparent, user-editable layer over the existing project
capabilities.  It is not a sandbox: on this host the user can already modify
source code, run Shell and access the database directly.  The policy presets
and approval preferences below only describe what the AI session is allowed to
do without asking.

Public entry points:

    python -m apiAnalysis.ai_cli capabilities --json
    python -m apiAnalysis.ai_cli policy show --access full-access --json
    python -m apiAnalysis.ai_cli run --access read-only --approval on-risk
    python -m apiAnalysis.ai_cli task chain-candidates --project-id <id> --json
    python -m apiAnalysis.ai_cli shell --approval never -- <command> <args...>
"""

__version__ = "0.1.0"
