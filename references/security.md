# Security and public hygiene

## CDP exposure

Chrome DevTools Protocol gives full browser control. Bind to loopback only:

```text
CHIP_RELAY_HOST=127.0.0.1
```

If remote access is needed, use SSH or Tailscale tunnels. Do not bind CDP to `0.0.0.0` on public networks.

## Never commit

- `profiles/`
- `.env`
- logs
- cookies
- browser cache
- downloaded Chromium/BrowserOS binaries
- screenshots containing logged-in sessions

## Cookie handling

If you export cookies through CDP, treat them as credentials. Scripts in this repo do not print cookie values.

## Bot detection note

CloakBrowser may reduce automation fingerprints. It is not a CAPTCHA-solving service and does not grant permission to access systems against their terms or controls. Use for legitimate testing, scraping where permitted, and agent workflows you are authorized to run.
