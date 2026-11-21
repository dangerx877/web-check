"""Role-based access control.

Three fixed roles keep the model auditable and easy to reason about:

* ``viewer``   – read-only: inventory, health, topology, saved configs, compliance reports.
* ``operator`` – viewer + run show commands, back up configs, request deployments.
* ``admin``    – everything, including config push, approving deployments, user/role management,
  vault export and settings.

Enforcement lives in :func:`require` so the UI, the CLI and background jobs share one policy.
Guest mode is an *ephemeral operator*: it can work on devices but cannot approve anything
and leaves no persistent credentials.
"""
from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"
    GUEST = "guest"          # internal: the ephemeral no-account session; never assignable to a user

    @classmethod
    def parse_assignable(cls, value: object) -> Role:
        """Parse a role an administrator may give to a user (guest is excluded)."""
        role = cls.parse(value)
        if role not in ASSIGNABLE_ROLES:
            raise ValueError(f"Unknown role {value!r}; choose one of: viewer, operator, admin.")
        return role

    @classmethod
    def parse(cls, value: object, default: Role | None = None) -> Role:
        if isinstance(value, cls):                      # str(Role.X) differs across Python versions
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            if default is not None:
                return default
            raise ValueError(f"Unknown role {value!r}; choose one of: {', '.join(r.value for r in cls)}.") from None


class Permission(str, Enum):
    VIEW = "view"
    RUN_SHOW = "run_show"
    BACKUP = "backup"
    EDIT_INVENTORY = "edit_inventory"
    PUSH_CONFIG = "push_config"
    REQUEST_DEPLOY = "request_deploy"
    APPROVE_DEPLOY = "approve_deploy"
    MANAGE_SCHEDULES = "manage_schedules"
    MANAGE_USERS = "manage_users"
    EXPORT_VAULT = "export_vault"
    CHANGE_SETTINGS = "change_settings"
    READ_AUDIT = "read_audit"


_P = Permission
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({_P.VIEW}),
    Role.OPERATOR: frozenset({_P.VIEW, _P.RUN_SHOW, _P.BACKUP, _P.EDIT_INVENTORY, _P.REQUEST_DEPLOY}),
    Role.ADMIN: frozenset(Permission),
    # Guest keeps the original single-user workflow (run, push, back up) but has no accounts, no
    # second person to approve things, and nothing durable to export or schedule.
    Role.GUEST: frozenset(Permission) - {_P.APPROVE_DEPLOY, _P.MANAGE_USERS, _P.EXPORT_VAULT, _P.MANAGE_SCHEDULES},
}
ASSIGNABLE_ROLES = (Role.VIEWER, Role.OPERATOR, Role.ADMIN)


class PermissionDenied(PermissionError):
    def __init__(self, role: Role, permission: Permission, reason: str = ""):
        msg = f"Your role ({role.value}) is not allowed to: {permission.value.replace('_', ' ')}"
        super().__init__(f"{msg} ({reason})." if reason else f"{msg}.")
        self.role, self.permission = role, permission


def can(role: Role | str, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[Role.parse(role)]


def require(role: Role | str, permission: Permission) -> None:
    r = Role.parse(role)
    if permission not in ROLE_PERMISSIONS[r]:
        raise PermissionDenied(r, permission)
