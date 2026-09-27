from __future__ import annotations

import hmac
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import FileResponse

from . import __version__
from .config import Settings, load_policy
from .executor import Executor, HexStrikeExecutor
from .models import (
    ApprovalRequest,
    AuditRecord,
    EvaluationRequest,
    JobRecord,
    JobRequest,
    JobStatus,
    PolicyEvaluation,
)
from .policy import PolicyEngine
from .store import Store


def create_app(settings: Settings | None = None, executor: Executor | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    policy = PolicyEngine(load_policy(settings.policy_path))
    store = Store(settings.database_path)
    executor = executor or HexStrikeExecutor(
        settings.hexstrike_url,
        settings.request_timeout_seconds,
    )

    app = FastAPI(
        title="HexStrike Control Plane",
        version=__version__,
        description="Policy, approval, execution, and audit gateway for HexStrike AI.",
    )
    app.state.settings = settings
    app.state.policy = policy
    app.state.store = store
    app.state.executor = executor

    def authenticate(
        x_control_plane_key: Annotated[str | None, Header()] = None,
    ) -> None:
        if settings.auth_disabled:
            return
        if not settings.api_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="CONTROL_PLANE_API_KEY is not configured",
            )
        if not x_control_plane_key or not hmac.compare_digest(
            x_control_plane_key,
            settings.api_key,
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")

    def actor(x_actor: Annotated[str | None, Header()] = None) -> str:
        value = (x_actor or "api-client").strip()
        return value[:120] or "api-client"

    protected = [Depends(authenticate)]

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(Path(__file__).parent / "static" / "index.html")

    @app.post("/v1/evaluate", response_model=PolicyEvaluation, dependencies=protected)
    def evaluate(request: EvaluationRequest) -> PolicyEvaluation:
        return policy.evaluate(request.tool, request.target)

    @app.post("/v1/jobs", response_model=JobRecord, status_code=201, dependencies=protected)
    def create_job(request: JobRequest, current_actor: str = Depends(actor)) -> JobRecord:
        evaluation = policy.evaluate(request.tool, request.target, request.arguments)
        job = store.create_job(request, evaluation, current_actor)
        store.append_audit(
            current_actor,
            "job.created",
            "job",
            job.id,
            {
                "tool": job.tool,
                "target": job.target,
                "decision": job.decision.value,
                "dry_run": job.dry_run,
            },
        )
        return job

    @app.get("/v1/jobs", response_model=list[JobRecord], dependencies=protected)
    def list_jobs(limit: Annotated[int, Query(ge=1, le=500)] = 100) -> list[JobRecord]:
        return store.list_jobs(limit)

    @app.get("/v1/jobs/{job_id}", response_model=JobRecord, dependencies=protected)
    def get_job(job_id: str) -> JobRecord:
        try:
            return store.get_job(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="job not found") from None

    @app.post("/v1/jobs/{job_id}/approve", response_model=JobRecord, dependencies=protected)
    def approve_job(
        job_id: str,
        request: ApprovalRequest,
        current_actor: str = Depends(actor),
    ) -> JobRecord:
        try:
            job = store.get_job(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="job not found") from None
        if job.status is not JobStatus.PENDING_APPROVAL:
            raise HTTPException(status_code=409, detail="job is not awaiting approval")
        if settings.require_separate_approver and current_actor == job.requester:
            raise HTTPException(
                status_code=409,
                detail="requester cannot approve their own elevated job",
            )
        try:
            updated = store.transition_job(
                job_id,
                {JobStatus.PENDING_APPROVAL},
                JobStatus.APPROVED,
                approved_by=current_actor,
                approval_reason=request.reason,
            )
        except RuntimeError:
            raise HTTPException(status_code=409, detail="job status changed before approval") from None
        store.append_audit(
            current_actor,
            "job.approved",
            "job",
            job_id,
            {"reason": request.reason},
        )
        return updated

    @app.post("/v1/jobs/{job_id}/run", response_model=JobRecord, dependencies=protected)
    def run_job(job_id: str, current_actor: str = Depends(actor)) -> JobRecord:
        try:
            job = store.get_job(job_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="job not found") from None
        if job.status not in {JobStatus.READY, JobStatus.APPROVED}:
            raise HTTPException(status_code=409, detail=f"job cannot run from {job.status.value}")

        try:
            store.transition_job(
                job_id,
                {JobStatus.READY, JobStatus.APPROVED},
                JobStatus.RUNNING,
                error=None,
            )
        except RuntimeError:
            raise HTTPException(status_code=409, detail="job is already being processed") from None
        store.append_audit(current_actor, "job.started", "job", job_id)
        try:
            result = executor.execute(store.get_job(job_id))
        except Exception as exc:
            failed = store.transition_job(
                job_id,
                {JobStatus.RUNNING},
                JobStatus.FAILED,
                error=str(exc)[:4000],
            )
            store.append_audit(
                current_actor,
                "job.failed",
                "job",
                job_id,
                {"error": str(exc)[:1000]},
            )
            return failed

        completed = store.transition_job(
            job_id,
            {JobStatus.RUNNING},
            JobStatus.SUCCEEDED,
            result=result,
            error=None,
        )
        store.append_audit(current_actor, "job.succeeded", "job", job_id)
        return completed

    @app.get("/v1/audit", response_model=list[AuditRecord], dependencies=protected)
    def list_audit(limit: Annotated[int, Query(ge=1, le=1000)] = 200) -> list[AuditRecord]:
        return store.list_audit(limit)

    @app.get("/v1/audit/verify", dependencies=protected)
    def verify_audit() -> dict[str, bool]:
        return {"valid": store.verify_audit_chain()}

    return app


app = create_app()

