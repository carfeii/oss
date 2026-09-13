https://github.com/tobychui/zoraxy/

## Finding 1: Path-exception rules for Basic Auth, ZorxAuth, and CAPTCHA match on raw string prefix, not a path boundary

## Disclosure

 - 8 Sep 2026 - reported via https://github.com/tobychui/zoraxy/security/advisories/GHSA-f34q-j94c-h4cf
 - 9 Sep 2026 - closed as maintainer has a no-AI policy
 - 13 Sep 2026 - disclosed

### Version
<= 3.3.4

## Summary

Three separate path-exception matchers, Basic Auth (`BasicAuthExceptionRules`), ZorxAuth SSO (`ZorxAuthExceptionRules`), and CAPTCHA (`ExceptionRules`), compare the request path against a configured prefix with a raw `strings.HasPrefix`, not a path-segment boundary. An operator who excludes `/public` from one of these controls to expose a single subtree also exposes every sibling path that shares the string as a prefix: `/publicAdminPanel`, `/public-internal`, `/publicapi/secret`, none of them the operator's intended subtree, all pass the exception check and skip the control entirely.

The forward-auth ignored-paths matcher in the same codebase (`mod/auth/sso/forward/ignoredpaths.go`) was already hardened against this exact class for issue #895, with a doc comment explaining the boundary/traversal risk. The three matchers here never got the same fix.

## Details

Basic Auth, `mod/dynamicproxy/authProviders.go`, `handleBasicAuth` (pre-fix):

```go
case AuthExceptionType_Paths:
	if strings.HasPrefix(r.RequestURI, exceptionRule.PathPrefix) {
		return nil
	}
```

ZorxAuth SSO, same file, `handleZorxAuth` (pre-fix):

```go
if strings.HasPrefix(r.URL.Path, rule.PathPattern) {
	return nil
}
```

CAPTCHA, `mod/dynamicproxy/captcha/captcha.go`, `CheckException` (pre-fix):

```go
case ExceptionTypePaths:
	if strings.HasPrefix(requestPath, rule.PathPrefix) {
		return true
	}
```

The same file already has a boundary-safe matcher, `pathPrefixMatch`, used by `ShouldEnforcePath` to decide which paths CAPTCHA protects in the first place. `CheckException`, which decides which paths bypass it, was never switched to use it.

## Proof of Concept

Go test against the Basic Auth handler:

```go
func TestHandleBasicAuth_ExceptionRuleBoundary(t *testing.T) {
	pe := &ProxyEndpoint{
		AuthenticationProvider: &AuthenticationProvider{
			AuthMethod: AuthMethodBasic,
			BasicAuthCredentials: []*BasicAuthCredentials{
				{Username: "admin", PasswordHash: "irrelevant-for-this-test"},
			},
			BasicAuthExceptionRules: []*BasicAuthExceptionRule{
				{RuleType: AuthExceptionType_Paths, PathPrefix: "/public"},
			},
		},
	}
	req := httptest.NewRequest("GET", "http://example.com/publicAdminPanel/secret", nil)
	w := httptest.NewRecorder()
	err := handleBasicAuth(w, req, pe)
	// pre-fix: err == nil, request served with no credentials
}
```

Result before the fix:

```
--- FAIL: TestHandleBasicAuth_ExceptionRuleBoundary (0.00s)
    BUG: /publicAdminPanel/secret bypassed Basic Auth via the /public exception rule, no credentials required
```

The CAPTCHA test reproduces the same bypass via `captcha.CheckException` with an identical path/prefix pair.

## Impact

Any deployment using a path-based exception rule on Basic Auth, ZorxAuth SSO, or CAPTCHA gates loses the guarantee that only the intended subtree is exempted. The severity depends on what sits behind the shared prefix on the proxied application: a path-restricted exception meant to expose a health check or webhook receiver can also expose an admin panel or API that happens to share the string prefix, with no authentication or CAPTCHA challenge at all.

Affected: `github.com/tobychui/zoraxy`, confirmed on commit `f9bc2074e425a3c6da9ac9064212d2b556f5f407` (current `main`), same as `v3.3.4`.

## Fix

Basic Auth and ZorxAuth now share a new `matchesAuthExceptionPrefix` helper in `authProviders.go`, mirroring the already-hardened `forward.requestPathWithinPrefix`:

```go
func matchesAuthExceptionPrefix(requestPath string, prefix string) bool {
	if prefix == "" {
		return false
	}
	cleanedPath := path.Clean("/" + requestPath)
	cleanedPrefix := path.Clean("/" + prefix)
	return cleanedPath == cleanedPrefix || strings.HasPrefix(cleanedPath, cleanedPrefix+"/")
}
```

CAPTCHA's `CheckException` now calls its own existing `pathPrefixMatch` instead of a raw `HasPrefix`. New tests lock in both the fix and that the intended exception path still works: `TestMatchesAuthExceptionPrefix_Boundary`, `TestHandleBasicAuth_ExceptionRuleBoundary` (`mod/dynamicproxy`), `TestCheckException_PathBoundary` (`mod/dynamicproxy/captcha`). `go test ./mod/dynamicproxy/... ./mod/auth/...` passes after the change.



## Finding 2: IP whitelist/blacklist bypass via spoofable X-Real-Ip and left-most X-Forwarded-For behind a trusted proxy

## Disclosure

 - 8 Sep 2026 - reported via [https://github.com/tobychui/zoraxy/security/advisories/GHSA-f34q-j94c-h4cf](https://github.com/tobychui/zoraxy/security/advisories/GHSA-h282-4fwg-9hf9)
 - 9 Sep 2026 - closed as maintainer has a no-AI policy
 - 13 Sep 2026 - disclosed

### Version
<= 3.3.4

## Summary

Zoraxy's reverse-proxy access control (IP whitelist/blacklist per access rule) resolves the requesting client's IP via `AccessRule.GetClientIP`, which calls `netutils.GetRequesterIP`. This function is only meant to trust proxy headers once the caller has confirmed the direct connection comes from a configured trusted proxy (the `TrustProxyHeadersOnly` feature, gated by `AccessRule.GetClientIP` in `mod/access/trustedProxy.go`). In practice the resolved value is still fully attacker-controlled, because:

1. `X-Real-Ip` is read first and trusted outright. Most CDNs and reverse proxies, including Cloudflare (whose IP ranges ship as the built-in default trusted-proxy list in `default_trusted_proxies.csv`), never set or overwrite this header, so a client-supplied value passes straight through unmodified.
2. `X-Forwarded-For` is parsed by taking the left-most (first) comma-separated entry. Per `X-Forwarded-For` semantics, each hop only appends its own observed source IP; a client can prepend an arbitrary value and it is never stripped by the proxy. Only the right-most entry is the one the directly-connected, already-verified trusted proxy itself appended.

Both are used for a security decision (IP whitelist/blacklist enforcement gating access to proxied backends, including zoraxy's own admin interface if it is reverse-proxied through itself), so this is a full authentication/access-control bypass for anyone able to route a request through a configured trusted proxy, which for the shipped default is simply "anyone who can reach the deployment through Cloudflare."

## Details

`mod/netutils/ipmatch.go`, function `GetRequesterIP` (pre-fix):

```go
func GetRequesterIP(r *http.Request) string {
	ip := r.Header.Get("X-Real-Ip")
	if ip == "" {
		CF_Connecting_IP := r.Header.Get("CF-Connecting-IP")
		Fastly_Client_IP := r.Header.Get("Fastly-Client-IP")
		if CF_Connecting_IP != "" {
			return CF_Connecting_IP
		} else if Fastly_Client_IP != "" {
			return Fastly_Client_IP
		}
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.RemoteAddr
	}
	requesterRawIp := ip
	if strings.Contains(requesterRawIp, ",") {
		requesterRawIp = strings.Split(requesterRawIp, ",")[0] // left-most, attacker-controlled
	}
	...
	return requesterRawIp
}
```

Caller, `mod/access/trustedProxy.go`:

```go
func (s *AccessRule) GetClientIP(r *http.Request) string {
	remoteIP := netutils.GetRequesterIPUntrusted(r)
	if s.TrustProxyHeadersOnly && s.parent != nil && s.parent.IsTrustedProxy(remoteIP) {
		return netutils.GetRequesterIP(r)
	}
	return remoteIP
}
```

`IsTrustedProxy` correctly checks that the direct TCP peer is a known trusted proxy IP/CIDR before calling into `GetRequesterIP` at all, which is the right idea. The bug is entirely inside `GetRequesterIP`: it never verifies that the header content it then trusts was actually produced by that trusted proxy rather than passed straight through from the client.

Enforcement path, `mod/dynamicproxy/access.go`, `accessRequestBlocked`:

```go
clientIpAddr := accessRule.GetClientIP(r)
if accessRule.IsBlacklisted(clientIpAddr) { ... return true, "blacklist" }
if !accessRule.IsWhitelisted(clientIpAddr) { ... return true, "whitelist" }
```

This is the live, per-request access-control check for every reverse-proxied route with an access rule attached.

## Proof of Concept

Go unit test, run against the unmodified source (`mod/netutils/ipmatch.go`, `mod/access/trustedProxy.go`, `mod/access/whitelist.go`, none of the project's own dependencies mocked):

```go
package access

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetClientIP_WhitelistBypassViaXRealIP(t *testing.T) {
	c, _ := newTestController(t)
	c.AddTrustedProxy("173.245.48.1", "cloudflare edge (simulated)")

	rule := &AccessRule{
		TrustProxyHeadersOnly: true,
		parent:                c,
	}

	whitelist := map[string]string{"198.51.100.7": "admin"}
	rule.WhiteListIP = &whitelist

	req := httptest.NewRequest(http.MethodGet, "http://target/admin", nil)
	req.RemoteAddr = "173.245.48.1:443"           // legitimate connection from the trusted proxy
	req.Header.Set("X-Real-Ip", "198.51.100.7")   // attacker spoofs the admin's IP

	clientIP := rule.GetClientIP(req)
	if clientIP != "198.51.100.7" {
		t.Fatalf("expected spoofed admin IP to be adopted as client IP, got %q", clientIP)
	}
	if !rule.IsIPWhitelisted(clientIP) {
		t.Fatalf("expected spoofed IP to pass the whitelist check")
	}
}
```

Result against the unmodified source:

```
=== RUN   TestGetClientIP_WhitelistBypassViaXRealIP
    BUG: attacker with no relation to 198.51.100.7 passed the IP whitelist by
    sending X-Real-Ip: 198.51.100.7 through the trusted proxy
--- PASS: TestGetClientIP_WhitelistBypassViaXRealIP (0.00s)
```

(equivalently, sending `X-Forwarded-For: 198.51.100.7, 203.0.113.9` through the same trusted proxy reproduces the bypass via the left-most-hop parsing bug instead of X-Real-Ip)

## Impact

Any client able to route a request through a configured trusted proxy, which for a stock installation is Cloudflare (preloaded automatically as the default trusted-proxy list), can:

- Bypass an IP whitelist gating access to a proxied backend or to zoraxy's own management interface, by spoofing an allow-listed admin IP.
- Bypass an IP blacklist, by spoofing any non-blacklisted IP.
- Pollute audit/event logs (`BlacklistedIPBlockedEvent`, request logs) and rate-limit/geo-IP decisions that key off the same client-IP resolution, with an attacker-chosen IP.

This defeats the entire purpose of the `TrustProxyHeadersOnly` feature: an operator who enables it specifically to get correct client IPs behind a CDN instead gets a value the CDN's own clients fully control.

Affected: `github.com/tobychui/zoraxy`, confirmed on release `v3.3.4` and current `main` branch. The trusted-proxy feature was introduced by commit `fa7c464` ("Add experimental trusted proxy in access rule"), included in `v3.3.4`.

## Fix

Rewrote `GetRequesterIP` (`mod/netutils/ipmatch.go`) to:

- Prefer `CF-Connecting-IP` / `Fastly-Client-IP` first (these are the only two headers a CDN is guaranteed to overwrite, never merely pass through).
- Fall back to `X-Forwarded-For`, taking the right-most entry (the hop the directly-connected trusted proxy itself appended) instead of the left-most, client-controlled entry.
- Stop trusting `X-Real-Ip` at all, since it has no append/chain semantics and most CDNs never set it, so it can't be distinguished from a client-supplied value.

```diff
 func GetRequesterIP(r *http.Request) string {
-	ip := r.Header.Get("X-Real-Ip")
-	if ip == "" {
-		CF_Connecting_IP := r.Header.Get("CF-Connecting-IP")
-		Fastly_Client_IP := r.Header.Get("Fastly-Client-IP")
-		if CF_Connecting_IP != "" {
-			return CF_Connecting_IP
-		} else if Fastly_Client_IP != "" {
-			return Fastly_Client_IP
-		}
-		ip = r.Header.Get("X-Forwarded-For")
+	CF_Connecting_IP := r.Header.Get("CF-Connecting-IP")
+	Fastly_Client_IP := r.Header.Get("Fastly-Client-IP")
+	if CF_Connecting_IP != "" {
+		return CF_Connecting_IP
+	} else if Fastly_Client_IP != "" {
+		return Fastly_Client_IP
 	}
+
+	ip := r.Header.Get("X-Forwarded-For")
 	if ip == "" {
 		ip = r.RemoteAddr
 	}
 	...
 	requesterRawIp := ip
 	if strings.Contains(requesterRawIp, ",") {
-		requesterRawIp = strings.Split(requesterRawIp, ",")[0]
+		parts := strings.Split(requesterRawIp, ",")
+		requesterRawIp = strings.TrimSpace(parts[len(parts)-1])
 	}
```

One existing test, `TestGetClientIP_TrustedCIDR_TrustsHeaders` in `mod/access/trustedProxy_test.go`, had encoded the vulnerable behavior as its expectation (asserting `X-Real-Ip` was trusted); it was updated to use `X-Forwarded-For` instead, and a new sibling test, `TestGetClientIP_TrustedCIDR_IgnoresXRealIP`, was added to lock in that `X-Real-Ip` is no longer trusted.

Re-run after the fix, against the same source tree:

```
=== RUN   TestGetClientIP_WhitelistBypassViaXRealIP
    fixed: GetClientIP resolved to "173.245.48.1" (not the spoofed admin IP),
    whitelist check correctly denied
--- PASS: TestGetClientIP_WhitelistBypassViaXRealIP (0.00s)
```

Full package test suites (`mod/netutils`, `mod/access`, `mod/dynamicproxy`, `mod/dynamicproxy/dpcore`, `mod/dynamicproxy/loadbalance`, `mod/dynamicproxy/modh2c`, `mod/dynamicproxy/permissionpolicy`, `mod/dynamicproxy/rewrite`) pass after the change, and `go build ./...` succeeds for the whole module.
