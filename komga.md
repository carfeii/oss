https://github.com/gotson/komga/

# Missing authorization check in KOReader sync API allows bypassing library/content restrictions (CWE-862)

**Affected versions <= 1.30.0**

## Summary

The KOReader sync API (`/koreader/syncs/progress`) does not enforce Komga's per-library content-restriction checks, letting any user with the `KOREADER_SYNC` role read and write reading-progress state for books in libraries that are not shared with them, as long as they know the book's KOReader content hash. Every other interface that resolves a book by an alternate identifier (the main REST API, and the Kobo sync API) calls the shared `ContentRestrictionChecker` before touching the resource; the KOReader sync controller never does.

## Details

`ContentRestrictionChecker` (`komga/src/main/kotlin/org/gotson/komga/interfaces/api/ContentRestrictionChecker.kt`) centralizes the `canAccessLibrary`/age-rating/label checks and is called from the main REST `BookController` and from the Kobo sync `KoboController` (e.g. `contentRestrictionChecker.checkContentRestrictionBook(principal.user, book)`).

`KoreaderSyncController` (`komga/src/main/kotlin/org/gotson/komga/interfaces/api/kosync/KoreaderSyncController.kt`) resolves a book purely by its KOReader content hash:

```kotlin
@GetMapping("syncs/progress/{bookHash}")
fun getProgress(
  @AuthenticationPrincipal principal: KomgaPrincipal,
  @PathVariable bookHash: String,
): DocumentProgressDto {
  val books = bookRepository.findAllByHashKoreader(bookHash)
  ...
}

@PutMapping("syncs/progress")
fun updateProgress(
  @AuthenticationPrincipal principal: KomgaPrincipal,
  @RequestBody koreaderProgress: DocumentProgressDto,
) {
  val books = bookRepository.findAllByHashKoreader(koreaderProgress.document)
  ...
  bookLifecycle.markProgression(book, principal.user, r2Progression)
}
```

Neither handler calls `ContentRestrictionChecker` at any point. `findAllByHashKoreader` performs an unscoped lookup across every library on the server, and `markProgression` persists a `READ_PROGRESS` row keyed only by `principal.user.id`, with no library check in between.

Authentication for this endpoint uses an API key via the `X-Auth-User` header, gated only by the `KOREADER_SYNC` role (`kosyncFilterChain` in `SecurityConfiguration.kt`), independent of library sharing. A user granted only this role, which has no stated connection to library visibility, can read and write progress for books outside every library ever shared with them.

The KOReader content hash is a deterministic hash of the book's file content (`hasherKoreader.computeHash(book.path)`), not treated as secret anywhere else in the KOReader sync protocol by design (that is how a KOReader client that already has the same file computes the same value without talking to the server first). This is a missing server-side authorization check, not something that depends on the hash being hard to obtain.

## Steps To Reproduce

Tested against commit `ff800c21253793d4d3fd855651b82d4924915950` (release `v1.30.0`), using the matching `gotson/komga:latest` Docker image.

1. Start Komga, claim the server as an admin account.
2. Create `LibraryA`, add one book, let it scan and finish media analysis. Enable `hashKoreader` on the library (`PATCH /api/v1/libraries/{id}` with `{"hashKoreader": true}`) and rescan so the book gets a `fileHashKoreader` value.
3. Create a second, unprivileged user (`POST /api/v2/users`) with only `USER`, `KOREADER_SYNC`, `FILE_DOWNLOAD`, `PAGE_STREAMING` roles.
4. Set that user's library sharing to exclude `LibraryA` (`PATCH /api/v2/users/{id}` with `{"sharedLibraries": {"all": false, "libraryIds": [<some other library id>]}}`).
5. As the restricted user, confirm `GET /api/v1/books/{bookId}` for `LibraryA`'s book returns `403 Forbidden`.
6. As the restricted user, create a personal API key: `POST /api/v2/users/me/api-keys` with `{"comment": "x"}`.
7. Send:
   ```
   PUT /koreader/syncs/progress
   X-Auth-User: <restricted user's API key>
   Content-Type: application/json

   {"document":"<LibraryA book's fileHashKoreader>","progress":"1","percentage":0.99,
    "device":"attacker-device","device_id":"attacker-id"}
   ```
   Returns `HTTP 200`, no authorization error.
8. `GET /koreader/syncs/progress/<same hash>` with the same `X-Auth-User` key returns `HTTP 200` with the progress written in step 7, for a book the same user gets `403` on via the main REST API.
9. Independently confirmed in the container's `database.sqlite` that a `READ_PROGRESS` row was persisted for this user against this book, with the test device identifiers, confirming a durable state change.

## Impact

Any user granted the `KOREADER_SYNC` role (a role with no apparent connection to library visibility, plausible to grant broadly) can use this endpoint to confirm whether a specific file exists anywhere on the server across every library regardless of their own library grants, and to write/read their own progress state against books in libraries explicitly withheld from them, including age-rating/label-restricted libraries intended for parental-control-style setups. This breaks Komga's library-sharing and content-restriction guarantee for this one access path, while the main REST API and Kobo sync API both enforce it correctly for the same underlying resource.

Suggested fix: call `contentRestrictionChecker.checkContentRestrictionBook(principal.user, book)` in both `getProgress` and `updateProgress` before further processing, mirroring `KoboController`'s existing calls for the equivalent lookups.

Affected versions: confirmed on commit `ff800c21253793d4d3fd855651b82d4924915950` / release `v1.30.0`.

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4, Medium)
CWE-862: Missing Authorization


## Disclosure
 - 4 Nov 2026 - opened https://github.com/gotson/komga/security/advisories/GHSA-9gjx-669m-v924
 - 4 Nov 2026 - closed without comments/reason
