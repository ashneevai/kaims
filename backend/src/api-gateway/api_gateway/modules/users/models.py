from __future__ import annotations

from enum import StrEnum


class SystemRole(StrEnum):
    # Canonical KaiMS operational roles.
    ADMIN = "ADMIN"
    HITL_APPROVER = "HITL_APPROVER"

    # Legacy roles retained temporarily for migration compatibility.
    ADMINISTRATOR = "Administrator"
    EXECUTIVE = "Executive"
    L3_ENGINEER = "L3 Engineer"
    L2_ENGINEER = "L2 Engineer"
    L1_OPERATOR = "L1 Operator"


CORE_OPERATIONAL_ROLES: tuple[str, ...] = (
    SystemRole.ADMIN.value,
    SystemRole.HITL_APPROVER.value,
)

LEGACY_ROLE_MIGRATION: dict[str, str] = {
    SystemRole.ADMINISTRATOR.value: SystemRole.ADMIN.value,
    SystemRole.L3_ENGINEER.value: SystemRole.HITL_APPROVER.value,
    SystemRole.L2_ENGINEER.value: SystemRole.HITL_APPROVER.value,
    SystemRole.L1_OPERATOR.value: SystemRole.HITL_APPROVER.value,
    SystemRole.EXECUTIVE.value: SystemRole.HITL_APPROVER.value,
}

SYSTEM_ROLES: tuple[str, ...] = tuple(role.value for role in SystemRole)
