https://github.com/eitchtee/WYGIWYH

# Missing object-level authorization on transaction, installment-plan, and recurring-transaction mutation endpoints (BOLA/IDOR)

Affected versions <= 0.24.0

## Summary

Any authenticated user who can merely *see* an Account (because its owner marked it `public`, or shared it with them) can edit, mute/unmute, mark paid/unpaid, move, clone, delete, and otherwise mutate every `Transaction`, `InstallmentPlan`, and `RecurringTransaction` record under that account, on a multi-user instance, without owning the account or the record.

This is the same broken object-level authorization class already fixed in GHSA-83g9-vjqf-2j5q (transaction-rule mutation endpoints) and GHSA-q668-h56g-mfp4 (import profiles/runs), left uncovered on the transaction-ledger models themselves. GHSA-q668's own text states "the transaction ledger stays protected by its owner-scoped managers" - that claim holds for *read*-level filtering, but not for the mutation endpoints, which perform no additional ownership check at all.

## Root cause

`Transaction`, `InstallmentPlan`, and `RecurringTransaction` (via its `TransferTemplate` base) are governed by their owning `Account`, which is a `SharedObject`. Their managers (`SoftDeleteManager`, `AllObjectsManager`, `GenericAccountOwnerManager` in `apps/transactions/models.py`) scope querysets using the same *visibility* predicate as `SharedObjectManager`:

```python
Q(account__visibility="public")
| Q(account__owner=user)
| Q(account__shared_with=user)
| Q(account__visibility="private", account__owner=None)
```

This is a READ-level check ("can the user see this?"), not an EDIT-level check ("can the user change this?"). The app's own documented contract for account sharing (`apps/common/forms.py`, `SharedObjectForm.visibility` help text) is explicit:

> Private: Only shown for the owner and shared users. Only editable by the owner.
> Public: Shown for all users. Only editable by the owner.

The project has an established, correctly-applied remediation pattern for exactly this problem:

- Web views: `get_shared_object_or_error(Model, request, id=pk, level=EDIT)` (`apps/common/functions/permissions.py`), which checks `SharedObject.is_editable_by()` (owner-only, regardless of visibility/shared_with) and is used correctly by `Account`, `AccountGroup`, `TransactionRule`, `TransactionCategory`/`Tag`/`Entity`, `ImportProfile`/`ImportRun`, and the DCA app's views.
- REST API: `SHARED_OBJECT_PERMISSIONS` / `SharedObjectPermission.has_object_permission()` (`apps/api/permissions.py`), whose own docstring says "writes are restricted to the owner here as well" - applied correctly to `TransactionCategoryViewSet`, `TransactionTagViewSet`, `TransactionEntityViewSet`, `AccountViewSet`, `AccountGroupViewSet`, and the rules/import/DCA viewsets.

Neither mechanism was ever applied to `Transaction`, `InstallmentPlan`, or `RecurringTransaction`, despite these models being governed by the identical Account-visibility semantics. Every mutation view in `apps/transactions/views/transactions.py`, `installment_plans.py`, and `recurring_transactions.py` fetches the target object with a bare `get_object_or_404(Model, id=...)` against the visibility-scoped manager and then mutates/deletes it with no further ownership check. The REST API's `TransactionViewSet`, `InstallmentPlanViewSet`, and `RecurringTransactionViewSet` (`apps/api/views/transactions.py`) likewise have no `permission_classes` override, so they fall back to the project's default (`NotInDemoMode` + `DjangoModelPermissions`), which is model-level only and has no notion of per-object ownership.

## Proof of concept

Reproduced against the published `eitchtee/wygiwyh:latest` image via the project's own `docker-compose.prod.yml`, with two ordinary (non-staff, non-superuser) users on the same instance.

1. Victim creates an Account ("Victim Private Checking") and marks its visibility `public` via the normal account-sharing UI (`POST /account/<id>/share/`). Per the app's own form help text this should mean "Shown for all users. Only editable by the owner."
2. Victim creates a Transaction, an InstallmentPlan, and a RecurringTransaction under that account.
3. Attacker, authenticated as an ordinary second user who was never granted ownership of the account and never shared anything with the victim, sends (no special privileges beyond being logged in and, for the account itself, merely seeing it because it is public):
   - `POST /transaction/<id>/edit/` -> rewrites `amount`, `description`, `notes` on the victim's transaction.
   - `DELETE /transaction/<id>/delete/` -> deletes the victim's transaction outright.
   - `GET /transaction/<id>/mute/`, `GET /transaction/<id>/pay/`, `GET /transaction/<id>/move-to-today/` -> toggle the victim's transaction state.
   - `GET /recurring-transactions/<id>/toggle-pause/` then `DELETE /recurring-transactions/<id>/delete/` -> pauses then deletes the victim's recurring transaction outright.
   - `GET /installment-plans/<id>/refresh/` then `DELETE /installment-plans/<id>/delete/` -> deletes the victim's installment plan outright.
   - `PATCH /api/transactions/<id>/` and `DELETE /api/transactions/<id>/` -> same read/write/delete via the REST API, confirmed with the attacker granted only the ordinary (non-staff) `add_transaction`/`change_transaction`/`delete_transaction`/`view_transaction` Django model permissions - the realistic configuration for a second household member account an administrator sets up to use the API.

Every one of the above was confirmed by reading the record back from the victim's own session/API afterward: edits persisted and deletions were permanent. The attacker at no point owned the account, the transaction, the installment plan, or the recurring transaction, and was never added to `shared_with` on anything - the account's `public` visibility (explicitly documented as read-only) was the only connection between the two users.

Sibling endpoints sharing the byte-identical vulnerable pattern (`get_object_or_404`/`.objects.all()` with no ownership check on a mutating view), reviewed but not individually exercised in this report's live test beyond the ones listed above: `transaction_clone`, `transaction_change_month`, `transaction_transfer_edit`, `transactions_bulk_edit`, `installment_plan_edit`, `recurring_transaction_edit`, `recurring_transaction_finish`, and the `transaction_convert_to_*` family in `apps/transactions/views/conversions.py`.

## Impact

On any multi-user instance, marking an account `public` (a documented, UI-exposed feature intended only to make it *visible* instance-wide) - or merely sharing it with another user for read access - silently also grants every such user full read/write/delete control over that account's entire transaction ledger: every transaction, installment plan, and recurring transaction, via both the web UI and the REST API. This directly contradicts the feature's own documented "Only editable by the owner" guarantee and is considerably more severe than the already-fixed GHSA-83g9 (which affected only transaction-rule automation, not the ledger itself) - here an attacker can fabricate, rewrite, or permanently destroy another user's actual financial records.

## Remediation

Apply the project's own existing fix pattern to the transaction-ledger surface:

- Web views (`apps/transactions/views/transactions.py`, `installment_plans.py`, `recurring_transactions.py`): replace the bare `get_object_or_404(Model, id=...)` calls in every mutating view with `get_shared_object_or_error(Model, request, id=pk, level=EDIT, via="account")` (or an equivalent explicit `account.owner == request.user` check), mirroring what `apps/accounts/views/accounts.py` already does.
- REST API (`apps/api/views/transactions.py`): add `permission_classes = SHARED_OBJECT_PERMISSIONS` with `shared_object_via = "account"` to `TransactionViewSet`, `InstallmentPlanViewSet`, and `RecurringTransactionViewSet`, mirroring `TransactionCategoryViewSet`/`TransactionTagViewSet`/`TransactionEntityViewSet`.

Single-user instances are not affected.

## Disclosure
 - 5 Nov 26 - reported via https://github.com/eitchtee/WYGIWYH/security/advisories/GHSA-36w2-769w-h62g
 - 14 Nov 26 - closed with reasons/comments
