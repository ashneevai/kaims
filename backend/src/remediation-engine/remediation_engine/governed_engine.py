from __future__ import annotations

from common.models import Approval, RemediationAction
from common.rollback_governance import apply_rollback_governance
from remediation_engine.safe_engine import SafeRemediationEngine


class GovernedRemediationEngine(SafeRemediationEngine):
    """Safe remediation engine with rollback/change-governance enforcement."""

    def build_action(self, approval: Approval) -> RemediationAction:
        action = super().build_action(approval)
        if action.action_type == "unsupported_capability":
            return action
        return apply_rollback_governance(approval=approval, action=action)
