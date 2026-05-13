# chip-relay

Public-safe browser relay skill for agent automation.

`chip-relay` launches a persistent local CDP browser and lets you switch between:

- **CloakBrowser** — stealth patched Chromium for automation-heavy pages.
- **BrowserOS** — Chromium-compatible browser path for GUI/MCP-style workflows.

It is designed to be copied into a Hermes skill directory or used standalone from a cloned repo.

## What this repo does not contain

- no cookies
- no API keys
- no private IPs or hostnames
- no hardcoded user accounts
- no browser profile data
- no downloaded browser binaries

## Install CloakBrowser path

```bash
scripts/install-cloakbrowser.sh
```

This creates:

```text
~/.local/share/chip-relay/cloakbrowser-venv/
~/.local/bin/cloakbrowser-chrome
```

The wrapper injects CloakBrowser fingerprint flags before normal Chromium/CDP flags.

## Install BrowserOS path

Install BrowserOS using the official project instructions, then ensure `browseros` is on `PATH`.

Linux `.deb` example:

```bash
curl -fsSL "https://cdn.browseros.com/download/BrowserOS.deb" -o /tmp/browseros.deb
sudo dpkg -i /tmp/browseros.deb
sudo apt-get install -f -y
```

## Configuration

Copy the template if you want stable local settings:

```bash
cp templates/chip-relay.env.example .env
```

Then edit `.env`. The script auto-loads `.env` from the repo root when present.

Key variables:

```text
CHIP_RELAY_BACKEND=auto|cloakbrowser|browseros|chromium
CHIP_RELAY_PORT=18800
CHIP_RELAY_HOST=127.0.0.1
CHIP_RELAY_PROFILE_DIR=~/.local/share/chip-relay/profiles/default
CHIP_RELAY_DISPLAY=:1002
CHIP_RELAY_HEADLESS=0|1
CLOAKBROWSER_FINGERPRINT_PLATFORM=windows|macos
```

## Commands

```bash
scripts/chip-relay doctor
scripts/chip-relay status
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay launch --backend browseros
scripts/chip-relay open https://example.com
scripts/chip-relay tabs
scripts/chip-relay health
scripts/chip-relay kill
```

## Backend switching

Switching is just relaunching with a different backend:

```bash
scripts/chip-relay kill
scripts/chip-relay launch --backend browseros
scripts/chip-relay status

scripts/chip-relay kill
scripts/chip-relay launch --backend cloakbrowser
scripts/chip-relay status
```

`auto` tries CloakBrowser first, then BrowserOS, then system Chromium.

## CDP use

Connect Playwright:

```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.connect_over_cdp("http://127.0.0.1:18800")
    page = browser.contexts[0].new_page()
    page.goto("https://example.com")
    print(page.title())
    browser.close()
```

## Systemd watchdog example

```ini
# ~/.config/systemd/user/chip-relay.service
[Unit]
Description=chip-relay browser CDP

[Service]
Type=simple
WorkingDirectory=%h/chip-relay
ExecStart=%h/chip-relay/scripts/chip-relay launch --backend auto --foreground
ExecStop=%h/chip-relay/scripts/chip-relay kill
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now chip-relay.service
```

## Public hygiene checks

```bash
python3 tests/test_public_hygiene.py
python3 tests/test_shell_syntax.py
python3 /path/to/create-skill/scripts/skill_workflow_guard.py .
```
