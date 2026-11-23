https://github.com/kcal-app/kcal/

# Missing ownership check lets any logged-in user read, delete and re-point other users' private journal data

**Affected versions <= 0.9.0**

Affected: kcal v0.9.0, commit 2514d7937f17681cfcf502ebb547751df43ecf14.

## Summary
`JournalEntryController::delete/destroy` and `JournalDateController::updateGoal` load their route-bound model without any ownership check. Any authenticated non-admin user can open the delete-confirmation page of another user's journal entry (which renders the entry), delete it, and change the goal attached to another user's journal date to any goal id. The README states that journal entries are private, and the sibling `goals` routes are protected by `can:access,goal`.

## Details
routes/auth.php registers `Route::resource('journal-entries', ...)`, `GET /journal-entries/{journal_entry}/delete` and `POST /journal-dates/{journal_date}/update/goal` with only the `auth` middleware. Goals, by contrast, use `->middleware(['can:access,goal'])` backed by `GoalPolicy::access` (`$user->id === $goal->user_id`).

app/Http/Controllers/JournalEntryController.php:

```php
public function delete(JournalEntry $journal_entry): View
{
    return view('journal-entries.delete')->with('journal_entry', $journal_entry);
}
public function destroy(JournalEntry $journal_entry): RedirectResponse
{
    $journal_entry->delete();
    ...
```

app/Http/Controllers/JournalDateController.php:

```php
public function updateGoal(Request $request, JournalDate $journalDate): RedirectResponse
{
    $attributes = $request->validate(['goal' => 'exists:App\Models\Goal,id']);
    $journalDate->goal()->associate($attributes['goal'])->save();
```

Neither checks `user_id`, and `exists:Goal,id` is not scoped to the caller. README: "Journal entries are private. Each user has and can only see their own entries."

### Steps To Reproduce
Setup (own container, kcal v0.9.0, sqlite): create two non-admin users with `php artisan user:add alice 'Passw0rd!x1'` and `php artisan user:add bob 'Passw0rd!x1'`; log both in at /login (cookie jars).
1. As bob: POST /goals (name, calories, days[]) and POST /journal-entries/create/from-nutrients (date, meal=0, summary=BobPrivateMeal, calories=500). Entry id 1, journal date id 1 belong to bob.
2. Control: as alice, GET /goals/1/edit and /goals/1/delete return 403 (GoalPolicy). Alice's own /journal-entries?date=... shows 0 matches for BobPrivateMeal.
3. As alice: GET /journal-entries/1/delete returns 200 and renders bob's entry (verified with two further entries, summaries and nutrients visible).
4. As alice: POST /journal-entries/1 with _method=DELETE and her CSRF token returns 302; bob's journal no longer lists the entry (database row gone).
5. As alice: POST /journal-dates/1/update/goal with goal=2 (alice's goal) returns 302; bob's journal page for that day now shows AliceGoal, linking /goals/2, which returns 403 for bob. Database: journal_dates id 1, user_id 2, goal_id 2.
A second, independent run with the roles swapped (bob as attacker against alice) reproduced steps 3-5 and the control.

## Impact
A low-privileged authenticated user can, by enumerating integer ids: read the summary and nutrient values of other users' private journal entries via the delete-confirmation page; permanently delete other users' journal entries; and make another user's journal day display a goal belonging to a different user. Demonstrated effects: entry text disclosure, entry deletion, goal re-pointing. Not demonstrated: assigning a goal that neither user owns (the `exists` rule is not scoped to the caller, so this is expected from the code, but it was not run); any effect beyond the kcal application data.

## Suggested fix
Apply the same ownership gate used for goals: add a policy (or a `can:` middleware) for `JournalEntry` and `JournalDate` that requires `$user->id === $model->user_id`, applied to `delete`, `destroy`, `updateGoal` and the other route-bound journal routes. In `updateGoal`, also scope the validation rule to the caller, for example `Rule::exists('goals','id')->where('user_id', $request->user()->id)`.

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N (5.4, Medium)


## Disclosure
 - 15 Nov 2026 - opened https://github.com/kcal-app/kcal/security/advisories/GHSA-g582-75cj-w472
 - 15 Nov 2026 - closed without comments/reason
