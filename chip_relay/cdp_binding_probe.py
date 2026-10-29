"""Bounded local compatibility probe; never repairs or re-registers a lost binding."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit


def probe_cdp_binding(page: Any, first_url: str, next_url: str) -> dict:
    """Call only on a task-owned synthetic page, never an account/third-party page.

    Reports both function availability and actual event delivery per document.
    Page.add_init_script is deliberately not used: it would mask engine drift.
    """
    urls = [urlsplit(url) for url in (first_url, next_url)]
    if any(u.scheme != 'http' or u.hostname != '127.0.0.1' or u.port is None or u.username or u.password
           or u.path not in {'/clean', '/init-script'} or u.query or u.fragment for u in urls):
        raise ValueError('local_binding_fixture_required')
    if urls[0].netloc != urls[1].netloc:
        raise ValueError('same_local_binding_fixture_required')
    page.goto(first_url, wait_until='load', timeout=5000)
    session = page.context.new_cdp_session(page)
    name = '__relayCompatibilityBinding'
    events: set[str] = set()
    stages = []

    def received(event: dict) -> None:
        if event.get('name') == name and event.get('payload') in {'initial', 'navigation', 'reload'}:
            events.add(event['payload'])

    try:
        session.on('Runtime.bindingCalled', received)
        session.send('Runtime.enable')
        session.send('Runtime.addBinding', {'name': name})
        for stage in ('initial', 'navigation', 'reload'):
            if stage == 'navigation':
                page.goto(next_url, wait_until='load', timeout=5000)
            elif stage == 'reload':
                page.reload(wait_until='load', timeout=5000)
            exists = page.evaluate(f'typeof window.{name}') == 'function'
            if exists:
                page.evaluate(f'payload => window.{name}(payload)', stage)
                deadline = time.monotonic() + 1.0
                while stage not in events and time.monotonic() < deadline:
                    page.wait_for_timeout(20)
            stages.append({'stage': stage, 'function_available': exists, 'event_received': stage in events})
    finally:
        session.detach()
    passed = all(s['function_available'] and s['event_received'] for s in stages)
    return {'schema': 'relay-cdp-binding-probe-v1', 'status': 'passed' if passed else 'needs_attention',
            'stages': stages, 'workaround_applied': False}
