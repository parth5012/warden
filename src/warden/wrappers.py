"""Aegis Logging & Audit Wrapper Decorators.

Provides production-grade decorators and context managers for:
1. Universal sync and async structured logging (@structured_log).
2. Direct Write-Ahead Journal integration (@audit_logged / @journal_event).
3. Automatic secret and credential scrubbing (OWASP & SECURITY_MODEL.md).
4. Execution context propagation across async tasks via contextvars.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import re
import sys
import time
import traceback
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union, cast

# Global logger for Aegis governance wrappers
logger = logging.getLogger("aegis.wrappers")

# Type variables for decorating functions while preserving signatures
F = TypeVar("F", bound=Callable[..., Any])

# ==============================================================================
# 1. EXECUTION CONTEXT PROPAGATION (contextvars)
# ==============================================================================

ctx_run_id: ContextVar[str] = ContextVar("ctx_run_id", default="run_system")
ctx_thread_id: ContextVar[str] = ContextVar("ctx_thread_id", default="thread_main")
ctx_actor: ContextVar[str] = ContextVar("ctx_actor", default="System")
ctx_action_id: ContextVar[Optional[str]] = ContextVar("ctx_action_id", default=None)
ctx_checkpoint_step: ContextVar[Optional[int]] = ContextVar("ctx_checkpoint_step", default=None)


class audit_context:
    """Context manager for scoping agent run provenance across async workflows.

    Usage:
        with audit_context(run_id="run_101", thread_id="t_1", actor="CodeAgent", action_id="act_99"):
            await executor.execute(...)
    """

    def __init__(
        self,
        run_id: Optional[str] = None,
        thread_id: Optional[str] = None,
        actor: Optional[str] = None,
        action_id: Optional[str] = None,
        checkpoint_step: Optional[int] = None,
    ) -> None:
        self.run_id = run_id
        self.thread_id = thread_id
        self.actor = actor
        self.action_id = action_id
        self.checkpoint_step = checkpoint_step
        self._tokens: List[Tuple[ContextVar[Any], Any]] = []

    def __enter__(self) -> "audit_context":
        if self.run_id is not None:
            self._tokens.append((ctx_run_id, ctx_run_id.set(self.run_id)))
        if self.thread_id is not None:
            self._tokens.append((ctx_thread_id, ctx_thread_id.set(self.thread_id)))
        if self.actor is not None:
            self._tokens.append((ctx_actor, ctx_actor.set(self.actor)))
        if self.action_id is not None:
            self._tokens.append((ctx_action_id, ctx_action_id.set(self.action_id)))
        if self.checkpoint_step is not None:
            self._tokens.append((ctx_checkpoint_step, ctx_checkpoint_step.set(self.checkpoint_step)))
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        for cvar, token in reversed(self._tokens):
            cvar.reset(token)

    async def __aenter__(self) -> "audit_context":
        return self.__enter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.__exit__(exc_type, exc_val, exc_tb)


def get_current_audit_context() -> Dict[str, Any]:
    """Returns the currently active execution context snapshot."""
    return {
        "run_id": ctx_run_id.get(),
        "thread_id": ctx_thread_id.get(),
        "actor": ctx_actor.get(),
        "action_id": ctx_action_id.get(),
        "checkpoint_step": ctx_checkpoint_step.get(),
    }


# ==============================================================================
# 2. SENSITIVE CREDENTIAL & SECRET REDACTION
# ==============================================================================

SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)(key|secret|token|password|passwd|auth|credential|api_key|priv_key|private|authorization)"
)


def redact_sensitive_data(obj: Any, depth: int = 0) -> Any:
    """Recursively scrub sensitive keys and credential patterns from arguments and payloads."""
    if depth > 10:
        return "<Max depth reached>"

    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if SENSITIVE_KEY_PATTERN.search(str(k)):
                cleaned[k] = "***REDACTED***"
            else:
                cleaned[k] = redact_sensitive_data(v, depth + 1)
        return cleaned
    elif isinstance(obj, list):
        return [redact_sensitive_data(item, depth + 1) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(redact_sensitive_data(item, depth + 1) for item in obj)
    elif isinstance(obj, set):
        return {redact_sensitive_data(item, depth + 1) for item in obj}
    elif isinstance(obj, str):
        # Scrub postgres URLs containing user:pass@host
        if "@" in obj and "://" in obj:
            return re.sub(r"://([^:@]+):([^@]+)@", r"://\1:***@", obj)
        return obj
    return obj


# ==============================================================================
# 3. JOURNAL STORE LINKAGE HOOK
# ==============================================================================

_JOURNAL_STORE_HOOK = None


def get_journal_store() -> Any:
    """Dynamically resolves the active JournalStore instance."""
    global _JOURNAL_STORE_HOOK
    if _JOURNAL_STORE_HOOK is not None:
        return _JOURNAL_STORE_HOOK

    # Attempt importing from app.audit
    try:
        from app.audit import JOURNAL_STORE
        return JOURNAL_STORE
    except Exception:
        return None


def set_journal_store(store: Any) -> None:
    """Manually override or bind the journal store adapter."""
    global _JOURNAL_STORE_HOOK
    _JOURNAL_STORE_HOOK = store


# ==============================================================================
# 4. STRUCTURED LOGGING WRAPPER DECORATOR (@structured_log)
# ==============================================================================

def structured_log(
    name: Optional[str] = None,
    log_level: int = logging.INFO,
    custom_logger: Optional[logging.Logger] = None,
    redact_args: bool = True,
    log_result: bool = True,
) -> Callable[[F], F]:
    """Universal logging decorator for synchronous and asynchronous functions.

    Logs:
    - {name}.started with sanitized arguments.
    - {name}.completed with execution latency in milliseconds.
    - {name}.failed with error details and traceback if an exception occurs.
    """
    def decorator(func: F) -> F:
        log_instance = custom_logger or logging.getLogger(f"aegis.{func.__module__}")
        func_name = name or func.__qualname__
        is_async = inspect.iscoroutinefunction(func)

        def _format_args(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
            bound_kwargs = dict(kwargs)
            # Add positional arguments with arg indices
            for i, arg in enumerate(args):
                bound_kwargs[f"arg_{i}"] = arg
            if redact_args:
                return cast(Dict[str, Any], redact_sensitive_data(bound_kwargs))
            return bound_kwargs

        if is_async:
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = get_current_audit_context()
                start_time = time.perf_counter()
                log_instance.log(
                    log_level,
                    f"{func_name}.started",
                    extra={
                        "function": func_name,
                        "context": ctx,
                        "fn_args": _format_args(args, kwargs),
                    },
                )
                try:
                    res = await func(*args, **kwargs)
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    extra_data = {
                        "function": func_name,
                        "context": ctx,
                        "duration_ms": duration_ms,
                    }
                    if log_result:
                        extra_data["result"] = redact_sensitive_data(str(res)[:500])
                    log_instance.log(log_level, f"{func_name}.completed", extra=extra_data)
                    return res
                except Exception as exc:
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    log_instance.error(
                        f"{func_name}.failed",
                        extra={
                            "function": func_name,
                            "context": ctx,
                            "duration_ms": duration_ms,
                            "error": redact_sensitive_data(str(exc)),
                            "error_type": type(exc).__name__,
                            "traceback": redact_sensitive_data(traceback.format_exc()),
                        },
                        exc_info=False,
                    )
                    raise
            return async_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = get_current_audit_context()
                start_time = time.perf_counter()
                log_instance.log(
                    log_level,
                    f"{func_name}.started",
                    extra={
                        "function": func_name,
                        "context": ctx,
                        "fn_args": _format_args(args, kwargs),
                    },
                )
                try:
                    res = func(*args, **kwargs)
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    extra_data = {
                        "function": func_name,
                        "context": ctx,
                        "duration_ms": duration_ms,
                    }
                    if log_result:
                        extra_data["result"] = redact_sensitive_data(str(res)[:500])
                    log_instance.log(log_level, f"{func_name}.completed", extra=extra_data)
                    return res
                except Exception as exc:
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    log_instance.error(
                        f"{func_name}.failed",
                        extra={
                            "function": func_name,
                            "context": ctx,
                            "duration_ms": duration_ms,
                            "error": redact_sensitive_data(str(exc)),
                            "error_type": type(exc).__name__,
                            "traceback": redact_sensitive_data(traceback.format_exc()),
                        },
                        exc_info=False,
                    )
                    raise
            return sync_wrapper  # type: ignore[return-value]

    return decorator


# ==============================================================================
# 5. WRITE-AHEAD JOURNAL & AUDIT LOG DECORATOR (@audit_logged)
# ==============================================================================

def audit_logged(
    kind_start: Optional[str] = "execution_started",
    kind_success: Optional[str] = "action_completed",
    kind_error: Optional[str] = "action_failed",
    actor: Optional[str] = None,
    action_id_arg: Optional[str] = None,
    description: Optional[str] = None,
    record_journal: bool = True,
    custom_logger: Optional[logging.Logger] = None,
) -> Callable[[F], F]:
    """Production Write-Ahead Logging decorator.

    Wraps a critical function (e.g. GuardedExecutor.execute, policy evaluation, sandbox execution):
    1. Emits a write-ahead event (`kind_start`) to the append-only journal BEFORE execution.
    2. Executes the wrapped callable (handling both sync and async functions).
    3. Emits a completion event (`kind_success`) with sanitized output upon success.
    4. Emits a failure event (`kind_error`) if an unhandled exception or denial occurs.
    """
    def decorator(func: F) -> F:
        log_instance = custom_logger or logging.getLogger(f"aegis.audit.{func.__module__}")
        func_name = func.__qualname__
        is_async = inspect.iscoroutinefunction(func)

        def _extract_action_id(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Optional[str]:
            # Priority 1: Check kwargs if explicit action_id_arg was designated
            if action_id_arg and action_id_arg in kwargs:
                val = kwargs[action_id_arg]
                return getattr(val, "id", str(val))

            # Priority 2: Check common action_id keys
            for k in ("action_id", "act_id", "action"):
                if k in kwargs:
                    val = kwargs[k]
                    return getattr(val, "id", str(val))

            # Priority 3: Check any argument that is an Action or dict with 'id'
            for v in kwargs.values():
                if hasattr(v, "id"):
                    return str(v.id)
                if isinstance(v, dict) and "id" in v:
                    return str(v["id"])

            for arg in args:
                if hasattr(arg, "id"):
                    return str(arg.id)
                if isinstance(arg, dict) and "id" in arg:
                    return str(arg["id"])

            # Priority 4: Fallback to contextvar
            return ctx_action_id.get()

        def _audit_arguments(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Dict[str, Any]:
            """Bind positional inputs to parameter names; fall back to raw args/kwargs."""
            try:
                bound = inspect.signature(func).bind_partial(*args, **kwargs)
                bound.apply_defaults()
                return dict(bound.arguments)
            except (TypeError, ValueError):
                return {"args": list(args), **kwargs}

        def _record_event(
            kind: str,
            status: str,
            desc: str,
            payload: Dict[str, Any],
            action_id: Optional[str],
            ctx: Dict[str, Any],
        ) -> Optional[str]:
            if not record_journal:
                return None

            store = get_journal_store()
            if not store:
                return None

            try:
                # Lazy import JournalEvent to prevent circular imports
                from app.audit import JournalEvent

                ev = JournalEvent(
                    id=f"ev_{uuid.uuid4().hex[:12]}",
                    run_id=ctx.get("run_id") or "run_default",
                    thread_id=ctx.get("thread_id") or "thread_default",
                    action_id=action_id,
                    checkpoint_step=ctx.get("checkpoint_step"),
                    kind=kind,
                    actor=actor or ctx.get("actor") or "System",
                    status=status,
                    description=desc,
                    payload=redact_sensitive_data(payload),
                    ts=datetime.now(timezone.utc).isoformat(),
                )
                store.append(ev)
                return ev.id
            except Exception as j_exc:
                log_instance.warning(
                    "audit_journal_append_warning",
                    extra={"error": str(j_exc), "kind": kind},
                )
                return None

        if is_async:
            @functools.wraps(func)
            async def async_audit_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = get_current_audit_context()
                act_id = _extract_action_id(args, kwargs)
                desc = description or f"Execute {func_name}"

                # 1. Write-Ahead event (Intent lock)
                if kind_start:
                    _record_event(
                        kind=kind_start,
                        status="Started",
                        desc=f"{desc} (started)",
                        payload={"function": func_name, "args": redact_sensitive_data(_audit_arguments(args, kwargs))},
                        action_id=act_id,
                        ctx=ctx,
                    )

                start_time = time.perf_counter()
                try:
                    res = await func(*args, **kwargs)
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                    # 2. Success Event
                    if kind_success:
                        _record_event(
                            kind=kind_success,
                            status="Succeeded",
                            desc=f"{desc} completed in {duration_ms}ms",
                            payload={
                                "function": func_name,
                                "duration_ms": duration_ms,
                                "result_preview": redact_sensitive_data(str(res)[:400]),
                            },
                            action_id=act_id,
                            ctx=ctx,
                        )
                    return res
                except Exception as exc:
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    # 3. Error Event
                    if kind_error:
                        _record_event(
                            kind=kind_error,
                            status="Failed",
                            desc=f"{desc} failed: {type(exc).__name__}",
                            payload={
                                "function": func_name,
                                "duration_ms": duration_ms,
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            },
                            action_id=act_id,
                            ctx=ctx,
                        )
                    raise

            return async_audit_wrapper  # type: ignore[return-value]
        else:
            @functools.wraps(func)
            def sync_audit_wrapper(*args: Any, **kwargs: Any) -> Any:
                ctx = get_current_audit_context()
                act_id = _extract_action_id(args, kwargs)
                desc = description or f"Execute {func_name}"

                # 1. Write-Ahead event (Intent lock)
                if kind_start:
                    _record_event(
                        kind=kind_start,
                        status="Started",
                        desc=f"{desc} (started)",
                        payload={"function": func_name, "args": redact_sensitive_data(_audit_arguments(args, kwargs))},
                        action_id=act_id,
                        ctx=ctx,
                    )

                start_time = time.perf_counter()
                try:
                    res = func(*args, **kwargs)
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

                    # 2. Success Event
                    if kind_success:
                        _record_event(
                            kind=kind_success,
                            status="Succeeded",
                            desc=f"{desc} completed in {duration_ms}ms",
                            payload={
                                "function": func_name,
                                "duration_ms": duration_ms,
                                "result_preview": redact_sensitive_data(str(res)[:400]),
                            },
                            action_id=act_id,
                            ctx=ctx,
                        )
                    return res
                except Exception as exc:
                    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    # 3. Error Event
                    if kind_error:
                        _record_event(
                            kind=kind_error,
                            status="Failed",
                            desc=f"{desc} failed: {type(exc).__name__}",
                            payload={
                                "function": func_name,
                                "duration_ms": duration_ms,
                                "error": str(exc),
                                "error_type": type(exc).__name__,
                            },
                            action_id=act_id,
                            ctx=ctx,
                        )
                    raise

            return sync_audit_wrapper  # type: ignore[return-value]

    return decorator
