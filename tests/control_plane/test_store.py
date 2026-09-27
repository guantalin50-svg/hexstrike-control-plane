from pathlib import Path

from control_plane.models import Decision, JobRequest, JobStatus, PolicyEvaluation
from control_plane.store import Store


def test_job_lifecycle_and_audit_chain(tmp_path: Path):
    store = Store(tmp_path / "control-plane.db")
    request = JobRequest(
        tool="nikto",
        target="app.test",
        justification="authorized staging validation",
    )
    evaluation = PolicyEvaluation(
        decision=Decision.APPROVAL,
        normalized_target="app.test",
        risk="elevated",
        reasons=["human approval required"],
    )

    job = store.create_job(request, evaluation, "requester")
    assert job.status is JobStatus.PENDING_APPROVAL

    approved = store.update_job(
        job.id,
        status=JobStatus.APPROVED,
        approved_by="approver",
        approval_reason="ticket SEC-1",
    )
    assert approved.approved_by == "approver"

    first = store.append_audit("requester", "job.created", "job", job.id)
    second = store.append_audit("approver", "job.approved", "job", job.id)
    assert second.previous_hash == first.event_hash
    assert store.verify_audit_chain() is True


def test_job_transition_is_compare_and_swap(tmp_path: Path):
    store = Store(tmp_path / "control-plane.db")
    request = JobRequest(
        tool="nmap",
        target="app.test",
        justification="authorized staging validation",
    )
    evaluation = PolicyEvaluation(
        decision=Decision.ALLOW,
        normalized_target="app.test",
        risk="standard",
        reasons=["allowed"],
    )
    job = store.create_job(request, evaluation, "requester")
    claimed = store.transition_job(job.id, {JobStatus.READY}, JobStatus.RUNNING)
    assert claimed.status is JobStatus.RUNNING

    try:
        store.transition_job(job.id, {JobStatus.READY}, JobStatus.RUNNING)
    except RuntimeError as exc:
        assert "status changed" in str(exc)
    else:
        raise AssertionError("a second worker claimed the same job")

