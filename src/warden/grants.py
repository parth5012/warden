"""User Grants: task-scoped, time-bound permission capabilities.

Defines the Grant model, ScopeRule matching logic, GrantsStore protocol,
and InMemoryGrantsStore reference adapter.
Zero dependencies on app/ (kernel-side module).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Protocol

from warden.policy.layers_static import is_scoped_drop_table


class GrantStatus(str, Enum):
    """Lifecycle statuses for a capability grant."""

    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    EXPIRED = "expired"
    REVOKED = "revoked"


def _is_safe_path_match(path: str, pfx: str) -> bool:
    """Check if path is strictly inside directory pfx without directory traversal."""
    if ".." in path:
        return False
    clean_pfx = pfx.rstrip("/")
    clean_path = path.rstrip("/")
    return clean_path == clean_pfx or path.startswith(clean_pfx + "/")


def _ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is offset-aware in UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class ScopeRule:
    """A single tool capability constraint within a grant."""

    tool: str
    constraints: dict[str, Any] = field(default_factory=dict)

    def matches(self, action_name: str, payload: dict[str, Any]) -> bool:
        """Check if action_name and payload satisfy this scope rule."""
        if self.tool != action_name and self.tool != "*":
            return False

        if not self.constraints:
            return True

        # 1. Path prefix constraints: validate ALL targets across payload
        path_pfx: str | None = None
        for pfx_key in ("path_prefix", "prefix", "path"):
            if pfx_key in self.constraints:
                path_pfx = str(self.constraints[pfx_key])
                break

        if path_pfx is not None:
            all_targets: list[str] = []
            if payload.get("path"):
                all_targets.append(str(payload["path"]))
            if payload.get("target_resource"):
                all_targets.append(str(payload["target_resource"]))
            raw_targets = payload.get("targets")
            if isinstance(raw_targets, list):
                all_targets.extend(str(t) for t in raw_targets)
            cmd = str(payload.get("cmd") or payload.get("command") or "")
            if cmd:
                tokens = cmd.split()
                all_targets.extend(t.strip("\"'") for t in tokens if not t.startswith("-") and t != "rm")

            if not all_targets or not all(_is_safe_path_match(t, path_pfx) for t in all_targets):
                return False

        # 2. General and structured constraints: all must match (fail-closed)
        for key, expected in self.constraints.items():
            if key in ("path_prefix", "prefix", "path"):
                continue

            if key == "table" and "table" not in payload and ("sql" in payload or "statement" in payload):
                sql_text = str(payload.get("sql", payload.get("statement", "")))
                is_scoped, tbl = is_scoped_drop_table(sql_text)
                if not is_scoped or tbl != str(expected):
                    return False
                continue

            if str(payload.get(key, "")) != str(expected):
                return False

        return True


@dataclass(frozen=True)
class Grant:
    """A human-issued, task-scoped, time-bound capability grant."""

    id: str
    thread_id: str
    granted_by: str
    scope: tuple[ScopeRule, ...] = field(default_factory=tuple)
    ttl_seconds: int = 1800  # Default 30 min per §7 (range 300..14400)
    max_uses: int = 5  # Default 5 uses per §7 (range 1..50)
    uses: int = 0
    status: GrantStatus = GrantStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            object.__setattr__(self, "created_at", self.created_at.replace(tzinfo=timezone.utc))

    def is_expired(self, now: datetime) -> bool:
        """Check if grant has exceeded its wall-clock TTL."""
        if self.status == GrantStatus.EXPIRED:
            return True
        now_utc = _ensure_utc(now)
        created_utc = _ensure_utc(self.created_at)
        elapsed = (now_utc - created_utc).total_seconds()
        return elapsed >= self.ttl_seconds

    def is_active(self, now: datetime) -> bool:
        """Check if grant is active and not expired, exhausted, or revoked."""
        if self.status != GrantStatus.ACTIVE:
            return False
        if self.uses >= self.max_uses:
            return False
        if self.is_expired(now):
            return False
        return True

    def matches(self, action_name: str, payload: dict[str, Any], now: datetime) -> bool:
        """Check if active grant covers action_name and payload."""
        if not self.is_active(now):
            return False
        return any(rule.matches(action_name, payload) for rule in self.scope)


class GrantsStore(Protocol):
    """Protocol for grant persistence and capability query."""

    def issue(self, grant: Grant) -> Grant:
        """Issue and record a new grant."""
        ...

    def get(self, grant_id: str) -> Grant | None:
        """Fetch grant by ID, updating status lazily if expired."""
        ...

    def list_for_thread(self, thread_id: str) -> list[Grant]:
        """List all grants for a given thread_id."""
        ...

    def find_covering_grant(
        self, thread_id: str, action_name: str, payload: dict[str, Any]
    ) -> Grant | None:
        """Find the first active grant covering the given action."""
        ...

    def consume(self, grant_id: str) -> tuple[Grant | None, int]:
        """Consume one use of grant. Returns (updated_grant, uses_left)."""
        ...

    def revoke(self, grant_id: str, revoked_by: str | None = None) -> Grant | None:
        """Revoke an active grant."""
        ...


class InMemoryGrantsStore:
    """In-memory reference adapter for GrantsStore with injectable clock."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._grants: dict[str, Grant] = {}

    def issue(self, grant: Grant) -> Grant:
        """Record and return a new grant."""
        now = self._clock()
        if grant.status == GrantStatus.ACTIVE and grant.is_expired(now):
            grant = replace(grant, status=GrantStatus.EXPIRED)
        self._grants[grant.id] = grant
        return grant

    def get(self, grant_id: str) -> Grant | None:
        """Get a grant by ID, updating status lazily if expired."""
        grant = self._grants.get(grant_id)
        if grant is None:
            return None
        now = self._clock()
        if grant.status == GrantStatus.ACTIVE and grant.is_expired(now):
            grant = replace(grant, status=GrantStatus.EXPIRED)
            self._grants[grant.id] = grant
        return grant

    def list_for_thread(self, thread_id: str) -> list[Grant]:
        """List all grants for a thread in creation order."""
        now = self._clock()
        res: list[Grant] = []
        for g in self._grants.values():
            if g.thread_id == thread_id:
                if g.status == GrantStatus.ACTIVE and g.is_expired(now):
                    g = replace(g, status=GrantStatus.EXPIRED)
                    self._grants[g.id] = g
                res.append(g)
        return sorted(res, key=lambda x: x.created_at)

    def find_covering_grant(
        self, thread_id: str, action_name: str, payload: dict[str, Any]
    ) -> Grant | None:
        """Find the first active grant for thread covering action_name and payload."""
        now = self._clock()
        for g in self.list_for_thread(thread_id):
            if g.matches(action_name, payload, now):
                return g
        return None

    def consume(self, grant_id: str) -> tuple[Grant | None, int]:
        """Consume one use of grant. Returns (updated_grant, uses_left)."""
        grant = self.get(grant_id)
        if grant is None or grant.status != GrantStatus.ACTIVE:
            return None, 0

        new_uses = grant.uses + 1
        new_status = GrantStatus.EXHAUSTED if new_uses >= grant.max_uses else GrantStatus.ACTIVE
        updated = replace(grant, uses=new_uses, status=new_status)
        self._grants[grant_id] = updated
        uses_left = max(0, grant.max_uses - new_uses)
        return updated, uses_left

    def revoke(self, grant_id: str, revoked_by: str | None = None) -> Grant | None:
        """Revoke an active grant."""
        grant = self.get(grant_id)
        if grant is None:
            return None
        if grant.status in (GrantStatus.EXHAUSTED, GrantStatus.EXPIRED, GrantStatus.REVOKED):
            return grant
        revoked = replace(grant, status=GrantStatus.REVOKED)
        self._grants[grant_id] = revoked
        return revoked


_GLOBAL_GRANTS_STORE: GrantsStore | None = None


def get_grants_store() -> GrantsStore:
    """Return the global GrantsStore instance, creating default in-memory store if unset."""
    global _GLOBAL_GRANTS_STORE
    if _GLOBAL_GRANTS_STORE is None:
        _GLOBAL_GRANTS_STORE = InMemoryGrantsStore()
    return _GLOBAL_GRANTS_STORE


def set_grants_store(store: GrantsStore | None) -> None:
    """Set the global GrantsStore instance (useful for test isolation)."""
    global _GLOBAL_GRANTS_STORE
    _GLOBAL_GRANTS_STORE = store
