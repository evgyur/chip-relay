"""Context-local integration seam for an explicitly selected external binding."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from copy import deepcopy
from .binding import verify_binding


@dataclass(frozen=True)
class AttachConfig:
    external_binding: dict | None = None
    selection: dict | None = None


_CURRENT = ContextVar("relay_attach_config", default=AttachConfig())


def load_config():
    return _CURRENT.get()


@contextmanager
def bound_config(entry, selection):
    """Trusted local use only. The registry runner validates the selection first."""
    verify_binding(entry)
    token = _CURRENT.set(AttachConfig(deepcopy(entry), deepcopy(selection)))
    try:
        yield load_config()
    finally:
        _CURRENT.reset(token)
