from __future__ import annotations

from api_gateway.modules.users.models import SystemRole

ADMIN_ROLES = {
    SystemRole.ADMIN.value,
    SystemRole.ADMINISTRATOR.value,
}

HITL_APPROVER_ROLES = {
    SystemRole.ADMIN.value,
    SystemRole.HITL_APPROVER.value,
    # Temporary migration aliases. Remove after legacy users are migrated.
    SystemRole.ADMINISTRATOR.value,
    SystemRole.L3_ENGINEER.value,
    SystemRole.L2_ENGINEER.value,
}

DOCUMENT_PROVIDER_ROLES = {
    *ADMIN_ROLES,
    SystemRole.HITL_APPROVER.value,
    SystemRole.L3_ENGINEER.value,
    SystemRole.L2_ENGINEER.value,
}

AUTHENTICATED_WRITE_RULES: tuple[tuple[set[str] | None, str, set[str] | None], ...] = (
    (None, "/applications", ADMIN_ROLES),
    (None, "/onboarding", ADMIN_ROLES),
    (None, "/monitoring", ADMIN_ROLES),
    ({"POST", "PUT", "DELETE", "PATCH"}, "/rag", DOCUMENT_PROVIDER_ROLES),
    ({"POST", "PUT", "DELETE", "PATCH"}, "/model", ADMIN_ROLES),
    ({"POST", "PUT", "DELETE", "PATCH"}, "/approval", HITL_APPROVER_ROLES),
)


def route_auth_rule(method: str, path: str) -> set[str] | None | bool:
    normalized_method = method.upper()
    normalized_path = path.rstrip("/") or "/"
    for methods, prefix, roles in AUTHENTICATED_WRITE_RULES:
        if methods is not None and normalized_method not in methods:
            continue
        if normalized_path == prefix or normalized_path.startswith(f"{prefix}/"):
            return roles
    return False
