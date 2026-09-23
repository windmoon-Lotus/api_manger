import os
import json
import unittest
import uuid
import datetime as dt

import redis

from apiAnalysis.tool.account_context import (
    AccountContext,
    AccountContextResolver,
    AccountContextUnavailable,
    CallbackAccountContextProvider,
)
from apiAnalysis.db.collection import (
    request_snapshot,
    security_execution_checkpoint,
    security_test_result,
    security_test_run,
)
from apiAnalysis.main import _ensure_mongo_connection
from apiAnalysis.tool import redis_pool
from apiAnalysis.tool.execution_contract import ExecutionContext
from apiAnalysis.tool.execution_scheduler import (
    WAKEUP_KEY,
    ExecutionPolicy,
    ExecutionWorker,
    enqueue_snapshot_batch,
    recover_expired_executions,
    request_execution_cancel,
    resume_auth_dependency,
    resume_execution,
    retry_execution,
)


@unittest.skipUnless(
    os.getenv("API_MANAGER_INTEGRATION_TESTS") == "1",
    "set API_MANAGER_INTEGRATION_TESTS=1 to use local MongoDB/Redis",
)
class ExecutionSchedulerIntegrationTests(unittest.TestCase):
    def setUp(self):
        _ensure_mongo_connection()
        suffix = uuid.uuid4().hex
        self.project_id = "scheduler-test-{}".format(suffix)
        self.queue_name = "scheduler-test-{}".format(suffix)
        self.snapshot_ids = []

    def tearDown(self):
        run_ids = list(security_test_run.objects(queue_name=self.queue_name).scalar("id"))
        if run_ids:
            security_test_result.objects(run_id__in=run_ids).delete()
            security_execution_checkpoint.objects(run_id__in=run_ids).delete()
            security_test_run.objects(id__in=run_ids).delete()
        if self.snapshot_ids:
            request_snapshot.objects(id__in=self.snapshot_ids).delete()
        try:
            client = redis.Redis(connection_pool=redis_pool)
            for run_id in run_ids:
                client.lrem(WAKEUP_KEY, 0, str(run_id))
        except Exception:
            pass

    def _snapshot(self, pathid, path, method="GET"):
        snapshot = request_snapshot(
            pathid=pathid,
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            method=method,
            url="https://scheduler.invalid{}".format(path),
            path=path,
            domain="scheduler.invalid",
            headers={},
        )
        snapshot.save()
        self.snapshot_ids.append(snapshot.id)
        return snapshot

    def test_enqueue_idempotency_worker_checkpoint_and_sanitized_results(self):
        first = self._snapshot(990001, "/blocked")
        second = self._snapshot(990002, "/public")
        context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
        )
        policy = ExecutionPolicy(max_workers=2, per_host_workers=2, min_interval_ms=0)
        run, created = enqueue_snapshot_batch(
            "integration batch",
            "unauth_access",
            context,
            [first.id, second.id],
            policy=policy,
            queue_name=self.queue_name,
        )
        self.assertTrue(created)
        duplicate, duplicate_created = enqueue_snapshot_batch(
            "renamed integration batch",
            "unauth_access",
            context,
            [second.id, first.id],
            policy=policy,
            queue_name=self.queue_name,
        )
        self.assertFalse(duplicate_created)
        self.assertEqual(run.id, duplicate.id)

        def fake_replay(snapshot, **_):
            status = 401 if snapshot.path == "/blocked" else 200
            return {
                "status_code": status,
                "expected_status_codes": [],
                "ok": status == 200,
                "elapsed_ms": 1.0,
                "response_len": 12,
                "response_sha256": ("a" if status == 401 else "b") * 64,
                "response_content_type": "application/json",
                "response_json_type": "object",
                "domain": snapshot.domain,
                "auth_mode": "anonymous",
                "text_sample": "must never persist",
                "error": "",
                "error_type": "",
            }

        worker = ExecutionWorker(
            worker_id="integration-worker",
            queue_name=self.queue_name,
            replay=fake_replay,
        )
        self.assertTrue(worker.run_once())
        run.reload()
        self.assertEqual(run.status, security_test_run.DONE)
        self.assertEqual(run.completed_cases, 2)
        self.assertEqual(run.summary["cluster_count"], 2)
        self.assertEqual(run.summary["review_candidate_count"], 1)
        self.assertEqual(
            security_execution_checkpoint.objects(run_id=run.id, status="done").count(),
            2,
        )
        results = list(security_test_result.objects(run_id=run.id))
        self.assertEqual({item.verdict for item in results}, {"no_vuln", "need_review"})
        self.assertTrue(all("text_sample" not in item.evidence_summary for item in results))

    def test_cancel_retry_and_expired_lease_recovery(self):
        snapshot = self._snapshot(990003, "/recover")
        context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
            plan_version="cancel-v1",
        )
        policy = ExecutionPolicy(max_workers=1, per_host_workers=1)
        cancelled, _ = enqueue_snapshot_batch(
            "cancel batch", "snapshot_baseline", context, [snapshot.id],
            policy=policy, queue_name=self.queue_name,
        )
        cancelled = request_execution_cancel(cancelled.id, reason="integration_cancel")
        self.assertEqual(cancelled.status, security_test_run.CANCELLED)
        self.assertEqual(cancelled.pending_cases, 0)
        self.assertEqual(cancelled.cancelled_cases, 1)
        self.assertEqual(
            security_execution_checkpoint.objects(run_id=cancelled.id).first().status,
            security_execution_checkpoint.CANCELLED,
        )
        retried, created = retry_execution(cancelled.id)
        self.assertTrue(created)
        self.assertEqual(retried.retry_of_run_id, cancelled.id)
        self.assertEqual(retried.status, security_test_run.QUEUED)
        request_execution_cancel(retried.id, reason="integration_cleanup")

        recovery_context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
            plan_version="recover-v1",
        )
        recovering, _ = enqueue_snapshot_batch(
            "recover batch", "snapshot_baseline", recovery_context, [snapshot.id],
            policy=policy, queue_name=self.queue_name,
        )
        token = "expired-integration-lease"
        expired = dt.datetime.utcnow() - dt.timedelta(seconds=1)
        security_test_run.objects(id=recovering.id).update_one(
            set__status=security_test_run.RUNNING,
            set__lease_owner="dead-worker",
            set__lease_token=token,
            set__lease_expires_at=expired,
        )
        security_execution_checkpoint.objects(run_id=recovering.id).update_one(
            set__status=security_execution_checkpoint.RUNNING,
            set__lease_token=token,
        )
        recovered = recover_expired_executions()
        self.assertGreaterEqual(recovered["recovered"], 1)
        recovering.reload()
        checkpoint = security_execution_checkpoint.objects(run_id=recovering.id).first()
        self.assertEqual(recovering.status, security_test_run.QUEUED)
        self.assertEqual(recovering.pending_cases, 1)
        self.assertEqual(recovering.running_cases, 0)
        self.assertEqual(checkpoint.status, security_execution_checkpoint.PENDING)
        request_execution_cancel(recovering.id, reason="integration_cleanup")

        preparing_context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
            plan_version="prepare-recover-v1",
        )
        preparing, _ = enqueue_snapshot_batch(
            "prepare recover batch", "snapshot_baseline", preparing_context, [snapshot.id],
            policy=policy, queue_name=self.queue_name,
        )
        security_execution_checkpoint.objects(run_id=preparing.id).delete()
        security_test_run.objects(id=preparing.id).update_one(
            set__status=security_test_run.PREPARING,
            set__updated_at=dt.datetime.utcnow() - dt.timedelta(minutes=10),
        )
        prepared = recover_expired_executions()
        self.assertGreaterEqual(prepared["preparing_recovered"], 1)
        preparing.reload()
        self.assertEqual(preparing.status, security_test_run.QUEUED)
        self.assertEqual(security_execution_checkpoint.objects(run_id=preparing.id).count(), 1)
        request_execution_cancel(preparing.id, reason="integration_cleanup")

    def test_missing_lease_is_requeued_and_legacy_running_row_expires(self):
        snapshot = self._snapshot(990009, "/orphaned")
        old = dt.datetime.utcnow() - dt.timedelta(days=2)
        orphan = security_test_run(
            name="orphaned managed run",
            project_id=self.project_id,
            env_id="test",
            check_type="snapshot_baseline",
            adapter_id="snapshot_batch",
            scheduler_managed=True,
            queue_name=self.queue_name,
            status=security_test_run.RUNNING,
            snapshot_ids=[snapshot.id],
            total_cases=1,
            running_cases=1,
            started_at=old,
        ).save()
        security_execution_checkpoint(
            run_id=orphan.id,
            snapshot_id=snapshot.id,
            project_id=self.project_id,
            env_id="test",
            pathid=snapshot.pathid,
            ordinal=0,
            status=security_execution_checkpoint.RUNNING,
        ).save()
        legacy = security_test_run(
            name="legacy stale run",
            project_id=self.project_id,
            env_id="test",
            check_type="legacy",
            scheduler_managed=False,
            status=security_test_run.RUNNING,
            started_at=old,
        ).save()

        summary = recover_expired_executions(
            now=dt.datetime.utcnow(),
            queue_name=self.queue_name,
            orphan_grace_seconds=60,
            legacy_stale_seconds=3600,
        )

        orphan.reload()
        legacy.reload()
        checkpoint = security_execution_checkpoint.objects(run_id=orphan.id).first()
        self.assertEqual(summary["orphaned_recovered"], 1)
        self.assertEqual(summary["legacy_expired"], 1)
        self.assertEqual(orphan.status, security_test_run.QUEUED)
        self.assertEqual(checkpoint.status, security_execution_checkpoint.PENDING)
        self.assertEqual(legacy.status, security_test_run.FAILED)
        self.assertEqual(legacy.last_error_type, "LegacyRunExpired")
        request_execution_cancel(orphan.id, reason="integration_cleanup")

    def test_unknown_adapter_pauses_before_replay_and_generic_mutation_requires_single_dispatch(self):
        snapshot = self._snapshot(990004, "/unsupported")
        context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="missing_adapter",
            plan_version="unsupported-v1",
        )
        run, _ = enqueue_snapshot_batch(
            "unsupported adapter", "snapshot_baseline", context, [snapshot.id],
            policy=ExecutionPolicy(max_workers=1, per_host_workers=1),
            queue_name=self.queue_name,
        )

        def must_not_replay(*_, **__):
            raise AssertionError("unsupported adapter sent a request")

        worker = ExecutionWorker(
            worker_id="integration-worker",
            queue_name=self.queue_name,
            replay=must_not_replay,
        )
        self.assertTrue(worker.run_once())
        run.reload()
        self.assertEqual(run.status, security_test_run.PAUSED)
        self.assertEqual(security_test_result.objects(run_id=run.id).count(), 0)
        self.assertEqual(resume_execution(run.id).status, security_test_run.QUEUED)
        request_execution_cancel(run.id, reason="integration_cleanup")

        mutation = self._snapshot(990005, "/mutation", method="POST")
        generic_context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            auth_mode="anonymous",
            adapter_id="snapshot_batch",
            plan_version="mutation-v1",
        )
        with self.assertRaisesRegex(ValueError, "max_dispatch_attempts=1"):
            enqueue_snapshot_batch(
                "generic mutation",
                "snapshot_baseline",
                generic_context,
                [mutation.id],
                policy=ExecutionPolicy(
                    max_workers=1,
                    per_host_workers=1,
                    allow_mutation=True,
                    mutation_acknowledged=True,
                ),
                queue_name=self.queue_name,
            )
        admitted, created = enqueue_snapshot_batch(
            "acknowledged generic mutation", "snapshot_baseline", generic_context,
            [mutation.id],
            policy=ExecutionPolicy(max_workers=1, per_host_workers=1,
                                   max_dispatch_attempts=1, allow_mutation=True,
                                   mutation_acknowledged=True),
            queue_name=self.queue_name,
        )
        self.assertTrue(created)
        self.assertEqual(admitted.status, security_test_run.QUEUED)
        request_execution_cancel(admitted.id, reason="integration_cleanup")

    def test_auth_dependency_resume_requires_the_exact_profile_revision(self):
        run = security_test_run(
            name="auth dependency",
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="auth_recipe",
            auth_context_ref="profile-revision-a",
            auth_profile_revision_id="profile-revision-a",
            auth_realm_revision_id="realm-revision-a",
            auth_adapter_version_id="adapter-version-a",
            adapter_id="authenticated_snapshot_batch",
            check_type="snapshot_baseline",
            status=security_test_run.PAUSED,
            scheduler_managed=True,
            queue_name=self.queue_name,
            pause_code="auth_unavailable",
            dependency_type="auth_profile",
            dependency_id="profile-revision-a",
            dependency_revision_id="profile-revision-a",
        )
        run.save()
        self.assertEqual(
            resume_auth_dependency(run.id, "profile-revision-b").status,
            security_test_run.PAUSED,
        )
        resumed = resume_auth_dependency(run.id, "profile-revision-a")
        self.assertEqual(resumed.status, security_test_run.QUEUED)
        self.assertFalse(resumed.dependency_type)
        request_execution_cancel(resumed.id, reason="integration_cleanup")

    def test_authenticated_adapter_uses_memory_context_and_missing_provider_pauses(self):
        snapshot = self._snapshot(990006, "/account")
        context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="callback_test",
            auth_context_ref="owner-current",
            adapter_id="authenticated_snapshot_batch",
            plan_version="account-v1",
        )
        run, _ = enqueue_snapshot_batch(
            "authenticated adapter", "snapshot_baseline", context, [snapshot.id],
            policy=ExecutionPolicy(max_workers=1, per_host_workers=1, min_interval_ms=0),
            queue_name=self.queue_name,
        )
        secret = "test-scheduler-memory-secret"
        seen = []

        def callback(reference):
            return AccountContext(
                project_id=reference.project_id,
                env_id=reference.env_id,
                account_id=reference.account_id,
                provider_id=reference.provider_id,
                context_ref=reference.effective_context_ref,
                headers={"Authorization": "Bearer {}".format(secret)},
                auth_kind="test_bearer",
                expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=5),
                allowed_hosts=["scheduler.invalid"],
            )

        resolver = AccountContextResolver([
            CallbackAccountContextProvider("callback_test", callback),
        ])

        def fake_replay(_snapshot, **kwargs):
            account_context = kwargs.get("account_context")
            self.assertIsNotNone(account_context)
            self.assertEqual(account_context.headers["Authorization"], "Bearer {}".format(secret))
            seen.append(account_context.descriptor())
            return {
                "status_code": 200,
                "expected_status_codes": [],
                "ok": True,
                "elapsed_ms": 1.0,
                "response_len": 12,
                "response_sha256": "c" * 64,
                "response_content_type": "application/json",
                "response_json_type": "object",
                "domain": "scheduler.invalid",
                "auth_mode": "account",
                "error_type": "",
            }

        worker = ExecutionWorker(
            worker_id="authenticated-integration-worker",
            queue_name=self.queue_name,
            replay=fake_replay,
            account_context_resolver=resolver,
        )
        self.assertTrue(worker.run_once())
        run.reload()
        self.assertEqual(run.status, security_test_run.DONE)
        self.assertEqual(len(seen), 1)
        self.assertEqual(run.auth_context_summary["header_names"], ["Authorization"])
        persisted = json.dumps(run.to_mongo().to_dict(), default=str)
        persisted += json.dumps([
            item.to_mongo().to_dict() for item in security_test_result.objects(run_id=run.id)
        ], default=str)
        self.assertNotIn(secret, persisted)

        expiring_snapshot = self._snapshot(990008, "/context-expired-before-send")
        expiring_context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="flaky_callback",
            adapter_id="authenticated_snapshot_batch",
            plan_version="account-expiry-v1",
        )
        expiring_run, _ = enqueue_snapshot_batch(
            "context expires before send", "snapshot_baseline", expiring_context,
            [expiring_snapshot.id],
            policy=ExecutionPolicy(max_workers=1, per_host_workers=1, min_interval_ms=0),
            queue_name=self.queue_name,
        )
        callback_count = []

        def flaky_callback(reference):
            callback_count.append(1)
            if len(callback_count) > 1:
                raise AccountContextUnavailable("test context unavailable")
            return AccountContext(
                project_id=reference.project_id,
                env_id=reference.env_id,
                account_id=reference.account_id,
                provider_id=reference.provider_id,
                context_ref=reference.effective_context_ref,
                headers={"Authorization": "Bearer {}".format(secret)},
                expires_at=dt.datetime.utcnow() + dt.timedelta(minutes=5),
                allowed_hosts=["scheduler.invalid"],
            )

        flaky_worker = ExecutionWorker(
            worker_id="flaky-auth-integration-worker",
            queue_name=self.queue_name,
            replay=lambda *_args, **_kwargs: self.fail("expired context sent a request"),
            account_context_resolver=AccountContextResolver([
                CallbackAccountContextProvider("flaky_callback", flaky_callback),
            ], cache_seconds=0),
        )
        self.assertTrue(flaky_worker.run_once())
        expiring_run.reload()
        self.assertEqual(expiring_run.status, security_test_run.PAUSED)
        self.assertEqual(expiring_run.pending_cases, 1)
        self.assertEqual(security_test_result.objects(run_id=expiring_run.id).count(), 0)

        missing_snapshot = self._snapshot(990007, "/missing-account")
        missing_context = ExecutionContext(
            project_id=self.project_id,
            env_id="test",
            account_id="owner",
            auth_mode="account",
            auth_provider_id="missing_provider",
            adapter_id="authenticated_snapshot_batch",
            plan_version="missing-account-v1",
        )
        missing_run, _ = enqueue_snapshot_batch(
            "missing account provider", "snapshot_baseline", missing_context,
            [missing_snapshot.id],
            policy=ExecutionPolicy(max_workers=1, per_host_workers=1),
            queue_name=self.queue_name,
        )
        no_provider_worker = ExecutionWorker(
            worker_id="missing-provider-integration-worker",
            queue_name=self.queue_name,
            replay=lambda *_args, **_kwargs: self.fail("missing provider sent a request"),
            account_context_resolver=AccountContextResolver(),
        )
        self.assertTrue(no_provider_worker.run_once())
        missing_run.reload()
        self.assertEqual(missing_run.status, security_test_run.PAUSED)
        self.assertEqual(missing_run.last_error_type, "AccountContextUnavailable")
        self.assertEqual(security_test_result.objects(run_id=missing_run.id).count(), 0)


if __name__ == "__main__":
    unittest.main()
