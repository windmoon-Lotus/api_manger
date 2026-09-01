"""Post-run verification & spot-check layer (audit subpackage).

Four independent checks that run AFTER a test round, reading only artifacts
the round already produced:

  boundary_audit  - what hosts/methods did the agent actually touch (transcript)
  evidence_verify - do stored verdicts recompute from their own evidence
  cleanup_audit   - did created test objects actually get removed (live sweep)
  coverage_report - tested / candidate / total denominators

The layer exists because agent self-reports are not verification; see the
2026-08 external-model eval postmortem.
"""
