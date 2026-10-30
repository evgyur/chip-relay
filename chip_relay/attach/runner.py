"""Cooperative same-UID action boundary for consumers of the attach-only library."""

from pathlib import Path
from .binding import BindingError, read_bindings, verify_binding
from .config import bound_config
from .profile_selection import read_selection, normalize_origin, digest
from .routing_contract import require_network


def authorize(binding_file, pin_file, *, session, target_url, profile=None):
    if not pin_file:
        raise BindingError("selection_required_for_routing_contract")
    bindings = read_bindings(Path(binding_file).expanduser())
    selected = read_selection(str(pin_file), bindings, profile, session)
    if normalize_origin(target_url) != selected["origin"]:
        raise BindingError("selection_destination_mismatch")
    require_network(selected)
    entry = bindings["profiles"][selected["profile"]]
    verify_binding(entry)
    return entry, selected


def run_checked(binding_file, pin_file, action, *, session, target_url, profile=None):
    """Revalidate before/after one trusted callable; never retry an uncertain effect.

    The callable receives the exact entry and pin. It must check the live provider
    identity before private reads/actions. This API is not a Python sandbox.
    """
    entry, selected = authorize(
        binding_file, pin_file, session=session, target_url=target_url, profile=profile
    )
    expected = (digest(entry), digest(selected))
    with bound_config(entry, selected):
        result = action(entry, selected)
    # Read files again: do not accept success from changed route/owner generations.
    after_entry, after_selection = authorize(
        binding_file, pin_file, session=session, target_url=target_url, profile=profile
    )
    if (digest(after_entry), digest(after_selection)) != expected:
        raise BindingError("selection_changed_during_action")
    return result
