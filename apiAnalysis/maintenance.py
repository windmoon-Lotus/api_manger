"""Idempotent maintenance operations for the dedicated scheduler process."""
from typing import Dict

from apiAnalysis.tool.execution_scheduler import recover_expired_executions
from apiAnalysis.tool.parameter_analysis import ParameterRelationAnalysisWorker
from apiAnalysis.tool.vulnerability_lifecycle import evaluate_completed_finding_retests


def run_maintenance_once(queue_name: str = "snapshot") -> Dict[str, object]:
    relation_worker = ParameterRelationAnalysisWorker(worker_id="maintenance-recovery")
    return {
        "execution": recover_expired_executions(queue_name=queue_name),
        "relation_analysis_requeued": relation_worker.recover_abandoned(),
        "finding_retests_evaluated": evaluate_completed_finding_retests(),
    }
