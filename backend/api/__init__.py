"""Backend REST API package."""

from warden.journal import InMemoryAuditJournal

# Shared audit journal for the API.  The GuardedLLMClient telemetry sink and
# every API audit endpoint read from this single append-only store so records
# are never duplicated or split across stores.
_shared_journal: InMemoryAuditJournal = InMemoryAuditJournal()


def get_audit_journal() -> InMemoryAuditJournal:
    """Return the shared InMemoryAuditJournal used by the API."""
    return _shared_journal
