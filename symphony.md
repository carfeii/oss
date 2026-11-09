https://github.com/88250/symphony/

# Nine admin routes in Symphony have no permission rule and are reachable without any authentication

**Affected versions <= 3.6.4**

Affected versions: confirmed on commit `ca6aa26161e809b6fd410afbe8347e8ec6443f7e` (2026-10-16, default branch HEAD); the same fail-open logic and missing-rule set is present in the latest tagged release, `v3.6.4` (2022-01-22).

## Summary

Every `/admin/*` route in Symphony is guarded only by `PermissionMidware`, which looks up the exact matched route (URI template + HTTP method) in a map built from `permission.rule.url.*` entries in `symphony.properties`. When a route has no matching entry, the middleware treats this as "nothing to check" and lets the request straight through to the handler, with no fallback authentication or authorization applied at all. Nine registered `/admin/*` routes have no corresponding `permission.rule.url.*` entry. Three of them perform a state-changing admin action and are reachable by a completely unauthenticated client: granting a one-time point credit to an arbitrary user, permanently deleting all currently-unused tags site-wide, and marking any abuse report as ignored.

## Details

`PermissionMidware.check()` (`src/main/java/org/b3log/symphony/processor/middleware/PermissionMidware.java`):

```java
final Set<String> requisitePermissions = Symphonys.URL_PERMISSION_RULES.get(rule);
if (null == requisitePermissions) {
    context.handle();
    return;
}
```

`rule` is built from the request's matched URI template and HTTP method (`permission.rule.url.<template>.<METHOD>`). `URL_PERMISSION_RULES` is populated once at startup from every `permission.rule.url.*` key present in `symphony.properties` (`src/main/java/org/b3log/symphony/util/Symphonys.java`). If a given `/admin/*` route's template+method combination has no matching key, the lookup returns `null` and the code falls through to `context.handle()`, running the handler with no check on the caller's session, role, or permissions.

`AdminProcessor.register()` wires every admin route through this single middleware and nothing else:

```java
final Handler[] middlewares = new Handler[]{permissionMidware::check};
Dispatcher.get("/admin/report/ignore/{reportId}", adminProcessor::makeReportIgnored, middlewares);
...
Dispatcher.post("/admin/tags/remove-unused", adminProcessor::removeUnusedTags, middlewares);
...
Dispatcher.post("/admin/user/{userId}/init-point", adminProcessor::initPoint, middlewares);
```

None of these three routes (nor six other, lower-impact `/admin/*` GET form-render routes) has a matching key in `src/main/resources/symphony.properties`'s `permission.rule.url.*` block, while every comparable neighboring admin route does (e.g. `permission.rule.url./admin/user/{userId}.POST=userUpdateUserBasic` exists, but no analogous key exists for `/admin/user/{userId}/init-point.POST`). The handlers perform no additional authorization check of their own:

```java
public void initPoint(final RequestContext context) {
    final String userId = context.pathVar("userId");
    ...
    final List<JSONObject> records = pointtransferQueryService.getLatestPointtransfers(
            userId, Pointtransfer.TRANSFER_TYPE_C_INIT, 1);
    if (records.isEmpty()) {
        final String transferId = pointtransferMgmtService.transfer(
                Pointtransfer.ID_C_SYS, userId, Pointtransfer.TRANSFER_TYPE_C_INIT,
                Pointtransfer.TRANSFER_SUM_C_INIT, userId, Long.valueOf(userId), "");
        ...
    }
}
```

```java
public void removeUnusedTags(final RequestContext context) {
    context.renderJSON(StatusCodes.SUCC);
    tagMgmtService.removeUnusedTags();
    ...
}
```

```java
public void makeReportIgnored(final RequestContext context) {
    final String reportId = context.pathVar("reportId");
    ...
    reportMgmtService.makeReportIgnored(reportId);
    ...
}
```

## Steps To Reproduce

1. Build and run Symphony from a clean checkout (MySQL backing store), with no account created and no login performed anywhere in the test client.
2. Confirm the test client has no session or authority by requesting an already-protected admin page: `curl -i http://<host>/admin/users` returns `403 Forbidden`.
3. `curl -i -X POST http://<host>/admin/tags/remove-unused` with no cookie header. Response is `500` (not `403`); the server log shows the request reached `AdminProcessor.removeUnusedTags` and `TagMgmtService.removeUnusedTags()` ran, deleting every currently-unused tag, before failing only on an unrelated audit-log null-user lookup.
4. `curl -i http://<host>/admin/report/ignore/1` with no cookie header (against an existing report id in a populated instance). Response reaches `AdminProcessor.makeReportIgnored` then `ReportMgmtService.makeReportIgnored`, marking the report ignored.
5. Register a normal user through the public sign-up flow to get a valid user id, then `curl -i -X POST http://<host>/admin/user/<that userId>/init-point` with no cookie header. Response is `302` redirecting to `/admin/user/<userId>`. A row is written to `symphony_pointtransfer` (`fromId=sys, toId=<userId>, type=0, sum=500`) and the target user's point balance increases by 500, confirmed by querying the database directly before and after the request.

## Impact

Any unauthenticated client that can reach a Symphony instance can grant a one-time 500-point credit to any user id of its choosing (repeatable per user until that user's own transfer history is later touched by an admin, since the only guard is "no existing INIT transfer for this user yet"), permanently delete every tag in the forum that currently has zero articles attached to it, and silently mark any pending abuse report as "ignored" so moderators stop seeing it in the open-reports queue. All three require no account, no CSRF token beyond what a trivial cross-site POST/GET already satisfies, and no interaction with any other user.

Suggested fix: add the missing `permission.rule.url.*` entries for these nine routes (matching the pattern already used for every comparable admin route), and consider changing `PermissionMidware.check()` to fail closed (deny) rather than fail open (allow) when a route has no matching rule, so a future route added to `AdminProcessor` without a corresponding properties entry cannot silently become unauthenticated by default.


## Disclosure 
 - 7 Nov 2026 - opened https://github.com/88250/symphony/security/advisories/GHSA-548h-vp3m-hjff
 - 7 nov 2026 - closed without comments/reason
