"""Human routing decisions and promotion for sanitized observations."""
import datetime as dt
from typing import Any, Dict, Tuple

from bson import ObjectId

from apiAnalysis.db.collection import (
    ApiProject,
    DataSource,
    ObservationRoutingDecision,
    ProjectAssetLink,
    ProjectEnvironment,
    ProjectSourceBinding,
    RequestObservation,
    request_sample,
    raw_data,
)
from apiAnalysis.project_context import ensure_data_source, ensure_source_binding


def _latest_decision(observation_id: str):
    return ObservationRoutingDecision.objects(
        observation_id=str(observation_id or "")
    ).order_by("-ctime", "-id").first()


def _load_target(observation_id: str, project_id: str, env_id: str):
    observation = RequestObservation.objects(
        observation_id=str(observation_id or "")
    ).first()
    project = ApiProject.objects(
        project_id=str(project_id or ""),
        status=ApiProject.ACTIVE,
    ).first()
    env_id = str(env_id or "").strip()
    if not observation or not project:
        raise ValueError("routing observation or project is unavailable")
    if env_id and not ProjectEnvironment.objects(
            project_id=project.project_id, env_id=env_id, active=True).first():
        raise ValueError("selected environment does not belong to the project")
    return observation, project, env_id


def _source_for_observation(observation: RequestObservation) -> DataSource:
    source = DataSource.objects(
        data_source_id=str(observation.data_source_id or "")
    ).first() if observation.data_source_id else None
    if source:
        return source
    external_id = str(
        observation.workspace_id
        or observation.source_id
        or observation.import_run_id
        or observation.observation_id
    )
    source = ensure_data_source(
        observation.source_type,
        external_id,
        name="{}:{}".format(observation.source_type, external_id),
        workspace_id=str(observation.workspace_id or ""),
    )
    RequestObservation.objects(id=observation.id).update_one(
        set__data_source_id=source.data_source_id,
    )
    observation.data_source_id = source.data_source_id
    return source


def _candidate_rows(
    latest,
    selected_project_id: str,
    reason_code: str = "manual_project_confirmation",
):
    candidates = []
    for item in list(latest.candidate_projects or []):
        if not isinstance(item, dict):
            continue
        candidates.append({
            "project_id": str(item.get("project_id") or "")[:100],
            "score": float(item.get("score") or 0.0),
            "reason_codes": [
                str(code)[:120]
                for code in list(item.get("reason_codes") or [])[:30]
            ],
        })
    selected = next(
        (
            item for item in candidates
            if item.get("project_id") == selected_project_id
        ),
        None,
    )
    if selected is None:
        selected = {"project_id": selected_project_id}
        candidates.append(selected)
    selected["score"] = 1.0
    selected["reason_codes"] = [reason_code]
    return candidates


def _signature_key(observation: RequestObservation) -> str:
    signature = str(observation.abstract_signature or "").strip()
    if not signature:
        return ""
    return "{} {}".format(
        str(observation.method or "GET").upper(),
        signature,
    )


def _teach_binding(
    binding: ProjectSourceBinding,
    observation: RequestObservation,
) -> None:
    signature_key = _signature_key(observation)
    if not signature_key:
        return
    rules = dict(binding.routing_rules or {})
    signatures = {
        str(item) for item in list(rules.get("signatures") or []) if item
    }
    signatures.add(signature_key)
    rules["signatures"] = sorted(signatures)
    binding.routing_rules = rules
    binding.mtime = dt.datetime.utcnow()
    binding.save()


def _unteach_binding(
    data_source_id: str,
    project_id: str,
    env_id: str,
    observation: RequestObservation,
) -> bool:
    signature_key = _signature_key(observation)
    if not signature_key:
        return False
    binding = ProjectSourceBinding.objects(
        data_source_id=str(data_source_id or ""),
        project_id=str(project_id or ""),
        env_id=str(env_id or ""),
        active=True,
    ).first()
    if not binding:
        return False
    rules = dict(binding.routing_rules or {})
    signatures = {
        str(item) for item in list(rules.get("signatures") or []) if item
    }
    if signature_key not in signatures:
        return False
    signatures.remove(signature_key)
    rules["signatures"] = sorted(signatures)
    binding.routing_rules = rules
    binding.mtime = dt.datetime.utcnow()
    binding.save()
    return True


def _detach_old_asset_link(
    observation: RequestObservation,
    project_id: str,
    env_id: str,
    relationship: str,
) -> None:
    if not observation.sample_id:
        return
    try:
        sample = request_sample.objects(id=ObjectId(observation.sample_id)).first()
    except Exception:
        sample = None
    asset = sample.raw_data if sample else None
    if not asset:
        return
    if str(sample.project_id or "") == str(project_id or ""):
        sample.project_id = ""
        sample.env_id = ""
        sample.save()
    other_project_samples = request_sample.objects(
        raw_data=asset,
        project_id=str(project_id or ""),
    ).count()
    if (
        not other_project_samples
        and str(asset.project_id or "") == str(project_id or "")
    ):
        raw_data.objects(pk=asset.pk).update_one(
            set__project_id="",
            set__env_id="",
        )
    link = ProjectAssetLink.objects(
        project_id=str(project_id or ""),
        pathid=int(asset.ptah_id),
        env_id=str(env_id or ""),
    ).first()
    if not link:
        return
    remaining = [
        item for item in list(link.observation_ids or [])
        if str(item) != observation.observation_id
    ]
    if remaining:
        link.observation_ids = remaining
    else:
        link.observation_ids = []
        link.relationship = relationship
        link.confidence = 0.0
        link.reason_codes = ["manual_route_{}".format(relationship)]
    link.mtime = dt.datetime.utcnow()
    link.save()


def _promote_existing_sample(
    observation: RequestObservation,
    project_id: str,
    env_id: str,
    previous_project_id: str = "",
    previous_env_id: str = "",
) -> Dict[str, Any]:
    """Attach a pre-existing bounded sample without inventing missing values."""
    if not observation.sample_id:
        return {"sample_promoted": False, "asset_linked": False}
    try:
        sample = request_sample.objects(id=ObjectId(observation.sample_id)).first()
    except Exception:
        sample = None
    if not sample:
        return {"sample_promoted": False, "asset_linked": False}

    asset = sample.raw_data
    if previous_project_id and previous_project_id != project_id:
        _detach_old_asset_link(
            observation,
            previous_project_id,
            previous_env_id,
            "superseded",
        )
    if asset and (
        not asset.project_id
        or str(asset.project_id) == str(previous_project_id or "")
    ):
        raw_data.objects(pk=asset.pk).update_one(
            set__project_id=project_id,
            set__env_id=env_id,
            set__import_run_id=str(
                observation.import_run_id or asset.import_run_id or ""
            ),
        )
        asset.project_id = project_id
        asset.env_id = env_id
    sample.project_id = project_id
    sample.env_id = env_id
    sample.import_run_id = str(
        observation.import_run_id or sample.import_run_id or ""
    )
    sample.observation_id = observation.observation_id
    sample.save()

    if not asset:
        return {"sample_promoted": True, "asset_linked": False}
    ProjectAssetLink.objects(
        project_id=project_id,
        pathid=int(asset.ptah_id),
        env_id=env_id,
    ).update_one(
        set__relationship="observed",
        set__confidence=1.0,
        set__reason_codes=["manual_project_confirmation"],
        add_to_set__observation_ids=observation.observation_id,
        set__mtime=dt.datetime.utcnow(),
        upsert=True,
    )
    return {
        "sample_promoted": True,
        "asset_linked": True,
        "pathid": int(asset.ptah_id),
    }


def assign_observation_project(
    observation_id: str,
    project_id: str,
    env_id: str = "",
    expected_decision_id: str = "",
    manual_by: str = "",
    teach_future: bool = True,
    override_final: bool = False,
) -> Tuple[ObservationRoutingDecision, Dict[str, Any]]:
    """Append a manual assignment and optionally teach the exact signature."""
    observation, project, env_id = _load_target(
        observation_id, project_id, env_id,
    )
    latest = _latest_decision(observation.observation_id)
    if not latest:
        raise ValueError("routing decision is unavailable")
    if expected_decision_id and str(latest.id) != str(expected_decision_id):
        raise ValueError("routing decision changed; reload before confirming")
    if latest.decision == ObservationRoutingDecision.ASSIGNED:
        if (
                latest.selected_project_id == project.project_id
                and str(latest.selected_env_id or "") == env_id):
            return latest, {
                "created": False,
                "sample_promoted": False,
                "asset_linked": False,
            }
    if (
        latest.decision in {
            ObservationRoutingDecision.ASSIGNED,
            ObservationRoutingDecision.IGNORED,
        }
        and not override_final
    ):
        raise ValueError("final routing decision requires explicit correction")

    source = _source_for_observation(observation)
    previous_project_id = str(latest.selected_project_id or "")
    previous_env_id = str(latest.selected_env_id or "")
    if latest.decision == ObservationRoutingDecision.ASSIGNED:
        _unteach_binding(
            source.data_source_id,
            previous_project_id,
            previous_env_id,
            observation,
        )
    binding = ensure_source_binding(
        source.data_source_id,
        project.project_id,
        env_id=env_id,
    )
    if teach_future:
        _teach_binding(binding, observation)

    reason_code = (
        "manual_project_override"
        if latest.decision in {
            ObservationRoutingDecision.ASSIGNED,
            ObservationRoutingDecision.IGNORED,
        }
        else "manual_project_confirmation"
    )
    decision = ObservationRoutingDecision(
        observation_id=observation.observation_id,
        selected_project_id=project.project_id,
        selected_env_id=env_id,
        candidate_projects=_candidate_rows(
            latest,
            project.project_id,
            reason_code,
        ),
        confidence=1.0,
        reason_codes=[reason_code],
        decision=ObservationRoutingDecision.ASSIGNED,
        rule_version="manual-v2",
        manual_by=str(manual_by or "")[:100],
    )
    decision.save()
    promoted = _promote_existing_sample(
        observation,
        project.project_id,
        env_id,
        previous_project_id=previous_project_id,
        previous_env_id=previous_env_id,
    )
    promoted.update({
        "created": True,
        "data_source_id": source.data_source_id,
        "binding_id": str(binding.id),
        "future_signature_taught": bool(teach_future),
    })
    return decision, promoted


def ignore_observation(
    observation_id: str,
    expected_decision_id: str = "",
    manual_by: str = "",
    reason: str = "manual_non_business_traffic",
    override_final: bool = False,
) -> ObservationRoutingDecision:
    """Append an auditable decision that excludes one observation."""
    observation = RequestObservation.objects(
        observation_id=str(observation_id or "")
    ).first()
    latest = _latest_decision(observation_id)
    if not observation or not latest:
        raise ValueError("routing observation or decision is unavailable")
    if expected_decision_id and str(latest.id) != str(expected_decision_id):
        raise ValueError("routing decision changed; reload before confirming")
    if latest.decision == ObservationRoutingDecision.IGNORED:
        return latest
    if (
        latest.decision == ObservationRoutingDecision.ASSIGNED
        and not override_final
    ):
        raise ValueError("assigned observation requires explicit correction")
    if latest.decision == ObservationRoutingDecision.ASSIGNED:
        source = _source_for_observation(observation)
        _unteach_binding(
            source.data_source_id,
            str(latest.selected_project_id or ""),
            str(latest.selected_env_id or ""),
            observation,
        )
        _detach_old_asset_link(
            observation,
            str(latest.selected_project_id or ""),
            str(latest.selected_env_id or ""),
            "ignored",
        )
    decision = ObservationRoutingDecision(
        observation_id=observation.observation_id,
        selected_project_id="",
        selected_env_id="",
        candidate_projects=list(latest.candidate_projects or []),
        confidence=1.0,
        reason_codes=[str(reason or "manual_non_business_traffic")[:120]],
        decision=ObservationRoutingDecision.IGNORED,
        rule_version="manual-v2",
        manual_by=str(manual_by or "")[:100],
    )
    decision.save()
    return decision


def deactivate_source_binding(
    binding_id: str,
    expected_data_source_id: str = "",
    manual_by: str = "",
) -> ProjectSourceBinding:
    try:
        object_id = ObjectId(str(binding_id or ""))
    except Exception:
        raise ValueError("source binding is unavailable") from None
    binding = ProjectSourceBinding.objects(id=object_id).first()
    if not binding:
        raise ValueError("source binding is unavailable")
    if (
        expected_data_source_id
        and binding.data_source_id != str(expected_data_source_id)
    ):
        raise ValueError("source binding changed; reload before disabling")
    if not binding.active:
        return binding
    binding.active = False
    binding.disabled_by = str(manual_by or "")[:100]
    binding.disabled_at = dt.datetime.utcnow()
    binding.mtime = binding.disabled_at
    binding.save()
    return binding
