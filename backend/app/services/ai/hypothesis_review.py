"""
Stage 9.2: Human Approval Workflow Service
Author: SentinelAPI Security Architecture Team

Manages the human-in-the-loop review lifecycle for AI hypotheses:
- Explicit approval with immutable audit logs.
- Explicit rejection with documented reasons and audit logs.
- Enforces single-review transitions (cannot approve/reject twice).
- Strictly non-executable: approval NEVER executes target API requests.
"""

from datetime import datetime, timezone
from typing import Tuple, Optional
from sqlalchemy.orm import Session

from app.models import (
    AIHypothesis,
    AIHypothesisReview,
    Project,
)
from app.services.ai.hypothesis_validator import HypothesisValidator, HypothesisValidationError


class HypothesisReviewError(ValueError):
    """Raised when an invalid review transition or review policy violation occurs."""
    pass


class HypothesisReviewService:
    """Coordinates approval, rejection, and audit recording for AI hypotheses."""

    def __init__(self, db: Session):
        self.db = db
        self.validator = HypothesisValidator(db)

    def approve_hypothesis(
        self,
        hypothesis_id: str,
        reviewer_reference: str,
        reason: Optional[str] = None,
    ) -> Tuple[AIHypothesis, AIHypothesisReview]:
        """
        Approve an AI hypothesis.
        Guarantees:
        - Must be in PENDING_REVIEW status.
        - Must pass full validator checks (schema, safety, project authorization).
        - Creates an immutable audit review record.
        - Updates hypothesis status to APPROVED.
        - ZERO target API HTTP requests are made.
        """
        if not reviewer_reference or not reviewer_reference.strip():
            raise HypothesisReviewError("Reviewer reference is required to approve an AI hypothesis.")

        hypothesis = self.db.query(AIHypothesis).filter(AIHypothesis.id == hypothesis_id).first()
        if not hypothesis:
            raise HypothesisReviewError(f"AI hypothesis '{hypothesis_id}' not found.")

        if hypothesis.status != "PENDING_REVIEW":
            raise HypothesisReviewError(
                f"Cannot approve hypothesis in '{hypothesis.status}' status. "
                f"Only hypotheses in 'PENDING_REVIEW' can be approved."
            )

        # Re-verify project authorization status
        project = self.db.query(Project).filter(Project.id == hypothesis.project_id).first()
        if not project or project.authorization_status != "authorized":
            status_desc = project.authorization_status if project else "NOT_FOUND"
            raise HypothesisReviewError(
                f"Cannot approve hypothesis: project {hypothesis.project_id} authorization status is '{status_desc}'."
            )

        # Validate hypothesis against security and isolation boundaries
        try:
            self.validator.validate(hypothesis)
        except HypothesisValidationError as ve:
            raise HypothesisReviewError(f"Hypothesis validation failed: {str(ve)}") from ve

        # Create immutable audit review record
        review_record = AIHypothesisReview(
            hypothesis_id=hypothesis.id,
            action="APPROVE",
            reviewer_reference=reviewer_reference.strip(),
            reason=reason.strip() if reason else None,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(review_record)

        # Transition hypothesis to APPROVED
        hypothesis.status = "APPROVED"
        hypothesis.reviewed_at = datetime.now(timezone.utc)
        hypothesis.reviewed_by = reviewer_reference.strip()
        hypothesis.rejection_reason = None

        self.db.commit()
        self.db.refresh(hypothesis)
        self.db.refresh(review_record)

        return hypothesis, review_record

    def reject_hypothesis(
        self,
        hypothesis_id: str,
        reviewer_reference: str,
        reason: str,
    ) -> Tuple[AIHypothesis, AIHypothesisReview]:
        """
        Reject an AI hypothesis with a documented reason.
        Guarantees:
        - Must be in PENDING_REVIEW status.
        - Must provide a non-empty rejection reason.
        - Creates an immutable audit review record.
        - Updates hypothesis status to REJECTED.
        - ZERO target API HTTP requests are made.
        """
        if not reviewer_reference or not reviewer_reference.strip():
            raise HypothesisReviewError("Reviewer reference is required to reject an AI hypothesis.")
        if not reason or not reason.strip():
            raise HypothesisReviewError("Rejection reason is mandatory when rejecting an AI hypothesis.")

        hypothesis = self.db.query(AIHypothesis).filter(AIHypothesis.id == hypothesis_id).first()
        if not hypothesis:
            raise HypothesisReviewError(f"AI hypothesis '{hypothesis_id}' not found.")

        if hypothesis.status != "PENDING_REVIEW":
            raise HypothesisReviewError(
                f"Cannot reject hypothesis in '{hypothesis.status}' status. "
                f"Only hypotheses in 'PENDING_REVIEW' can be rejected."
            )

        # Create immutable audit review record
        review_record = AIHypothesisReview(
            hypothesis_id=hypothesis.id,
            action="REJECT",
            reviewer_reference=reviewer_reference.strip(),
            reason=reason.strip(),
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(review_record)

        # Transition hypothesis to REJECTED
        hypothesis.status = "REJECTED"
        hypothesis.reviewed_at = datetime.now(timezone.utc)
        hypothesis.reviewed_by = reviewer_reference.strip()
        hypothesis.rejection_reason = reason.strip()

        self.db.commit()
        self.db.refresh(hypothesis)
        self.db.refresh(review_record)

        return hypothesis, review_record
