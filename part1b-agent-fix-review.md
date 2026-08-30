# Part 1B — Review of the Agent's Fix

The prompt was "fix the security issues in BookingController." A junior engineer approved the resulting
diff. Reviewing it as if it's one commit away from production.

## 1. What the patch fixes, and what it misses or breaks

**What it actually fixes:**

- `show()`: adds `Booking::where('customer_id', auth()->id())` before `findOrFail()`. This correctly closes
  the IDOR from Finding A1 — a customer can no longer fetch another customer's booking by ID. Good, real
  fix.
- `search()`: parameterizes `$zip` via a bound placeholder (`WHERE zip = ?`, `[$zip]`). This closes **half**
  of Finding A2.

**What it misses — and would look correct to a fast reviewer:**

1. **`$status` is still string-interpolated into the raw SQL.** Look at the "fixed" query again:

   ```php
   $rows = DB::select(
       "SELECT id, address, scheduled_for, status
        FROM bookings
        WHERE zip = ? AND status = '$status'
        ORDER BY scheduled_for DESC",
       [$zip]
   );
   ```

   `zip` is bound; `status` is not. This is **still SQL injection** — just on a different parameter. A
   request like `?status=active' UNION SELECT card_number,name,email,phone FROM customers--` (adjusted for
   column count) is exactly as exploitable today as it was before this patch. A reviewer scanning the diff
   sees "they added a `?` and a bindings array" and pattern-matches that to "SQLi fixed" without checking
   whether *every* interpolated value was bound — that's exactly the trap: partial parameterization reads as
   full parameterization at a glance. This is the single most dangerous miss in the patch, because it's the
   one most likely to be rubber-stamped.

2. **`search()` still has no ownership scope at all.** The patch doesn't touch Finding A3 — the query never
   filters by `customer_id`/`pro_id`. Even with `zip` and `status` fully parameterized, this endpoint still
   returns every customer's bookings in a given zip code to any authenticated caller. The agent was told
   "fix the security issues" and fixed the injection-shaped bug it could pattern-match against
   (interpolated SQL), but the BOLA — a data-model/business-logic gap, not a syntax pattern — wasn't
   recognized as a "security issue" at all. This is worth stating plainly: **fixing the injection did not
   fix the authorization problem, and they are independent bugs that both need independent fixes.**

3. **`update()` is untouched.** Still `$booking->update($request->all())`. The patch doesn't even attempt
   Finding A4.

**What it breaks — a new vulnerability the patch itself introduces:**

4. **The `$fillable` addition on `Booking` makes `pro_payout_cents` and `customer_id` mass-assignable.**

   ```php
   protected $fillable = [
       'address', 'scheduled_for', 'status', 'pro_payout_cents', 'customer_id',
   ];
   ```

   Before this patch, `Booking` declared no `$fillable`/`$guarded` at all, which means Laravel's default
   guard-everything behavior most likely made `$booking->update($request->all())` a no-op or a thrown
   `MassAssignmentException` in non-production — i.e., the mass-assignment risk flagged in Finding A4 was
   **latent, not live**. The agent, almost certainly trying to make `update()` actually persist changes
   during testing (a customer editing `address`/`scheduled_for` legitimately needs *some* fields fillable),
   added a `$fillable` array — but included `pro_payout_cents`, `customer_id`, and `status` alongside the
   genuinely safe fields. Combined with the fact that `update()`'s controller method still calls
   `$booking->update($request->all())` unchanged, this patch **converts a dormant risk into a live,
   trivially exploitable one**: any customer hitting `POST /api/v2/bookings/{id}` can now send
   `{"pro_payout_cents": 999999}` or `{"customer_id": <someone_else>}` in the body and have it persist.
   `customer_id` reassignment is particularly bad given `update()`'s own ownership check only runs at
   *lookup* time — nothing re-verifies ownership after the field changes, so a booking can be reassigned
   away from its rightful owner in the same request that "safely" looked it up.

   This is the finding most likely to be missed by both a fast human reviewer and a scanner tuned only to
   look at the controller diff: the dangerous change is in the **model file**, in a hunk labeled as
   incidental ("The agent also added this to `app/Models/Booking.php`"), while all the reviewer's attention
   was drawn to the controller's `show()`/`search()` hunks where the actual requested fix lived.

5. **Still no Policy/Gate-based authorization anywhere** — the patch reinforces the inline
   `where('customer_id', auth()->id())` pattern rather than moving to a Policy, so this fix has to be
   manually re-derived and re-reviewed for every future endpoint touching `Booking`, instead of being
   defined once.

6. Minor: the patch also doesn't remove `pro_payout_cents` from the `show()` response (the business-data
   overexposure noted in Finding A1) — not a regression, but a missed opportunity given the diff was already
   touching that exact response array.

## 2. Corrected version

```diff
--- a/app/Http/Controllers/Api/BookingController.php
+++ b/app/Http/Controllers/Api/BookingController.php
@@
-    public function show($id)
+    public function show(Request $request, $id)
     {
-        $booking = Booking::where('customer_id', auth()->id())->findOrFail($id);
+        $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);
         return response()->json([
             'id' => $booking->id,
             'address' => $booking->address,
             'customer' => $booking->customer->only(['name', 'email', 'phone']),
-            'pro_payout' => $booking->pro_payout_cents,
             'card_last4' => $booking->card_last4,
         ]);
     }
@@
     public function search(Request $request)
     {
-        $zip = $request->query('zip');
-        $status = $request->query('status', 'active');
-
-        $rows = DB::select(
-            "SELECT id, address, scheduled_for, status
-            FROM bookings
-            WHERE zip = ? AND status = '$status'
-            ORDER BY scheduled_for DESC",
-            [$zip]
-        );
+        $validated = $request->validate([
+            'zip'    => ['required', 'regex:/^\d{5}(-\d{4})?$/'],
+            'status' => ['sometimes', Rule::in(['active', 'completed', 'cancelled', 'pending'])],
+        ]);
+
+        $rows = Booking::query()
+            ->where('customer_id', $request->user()->id)
+            ->where('zip', $validated['zip'])
+            ->where('status', $validated['status'] ?? 'active')
+            ->orderByDesc('scheduled_for')
+            ->get(['id', 'address', 'scheduled_for', 'status']);
+
         return response()->json($rows);
     }
+
+    public function update(UpdateBookingRequest $request, $id)
+    {
+        $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);
+        $booking->update($request->validated());
+        return response()->json([
+            'id' => $booking->id,
+            'address' => $booking->address,
+            'scheduled_for' => $booking->scheduled_for,
+            'status' => $booking->status,
+        ]); // explicit shape, not $booking directly — $guarded doesn't limit serialization
+    }
```

```diff
--- a/app/Models/Booking.php
+++ b/app/Models/Booking.php
@@
-protected $fillable = [
-    'address', 'scheduled_for', 'status', 'pro_payout_cents', 'customer_id',
-];
+// Deny-list, not an allow-list: a new column added later defaults to guarded,
+// not fillable, unless someone deliberately removes it from this list.
+protected $guarded = [
+    'id', 'customer_id', 'pro_id', 'pro_payout_cents', 'status', 'card_last4',
+    'created_at', 'updated_at',
+];
```

(Full corrected files, including the `UpdateBookingRequest` that whitelists only
`scheduled_for`/`address`, are in `part1-find-and-fix/A-booking-controller/`.)

## 3. What stops this class of miss at agent speed

The uncomfortable truth here is that a fast human reviewer — junior or not — is exactly the wrong control
for "did every interpolated variable in this SQL string get parameterized" and "does this new `$fillable`
entry include a financial or identity column." Those are mechanical, exhaustive checks; humans are bad at
exhaustive under time pressure, which is precisely how this patch got approved. The fix is to stop asking a
human to catch this by eye and make each miss mechanically unshippable:

1. **A deny-list linter for `$fillable`.** A Semgrep/Larastan rule that flags any `$fillable` array (or
   `Model::create()`/`::update()` call operating on fillable-driven input) containing a field matching a
   sensitive-name pattern (`*_id`, `*_cents`, `*_amount`, `status`, `role`, `is_*`, `*_token`). This would
   have failed the build on this exact diff, on the exact line that mattered, without requiring anyone to
   notice it.

2. **A "fully bound or fully rejected" SQL rule**, not "contains a `?` somewhere.** The check should be:
   does this raw SQL string contain *any* `$variable` interpolation, regardless of whether other parts of
   the same query are already parameterized. Partial parameterization should fail the same gate as no
   parameterization — otherwise, as happened here, a partial fix reads as a complete one to both a
   Semgrep rule written naively ("contains `?`, must be safe") and a human skimming the diff. In practice:
   ban `DB::select`/`DB::statement`/`whereRaw` outside a small, explicitly reviewed allowlist of files, and
   require Eloquent/query-builder for everything else — that sidesteps the "is it *fully* bound" question
   by removing raw SQL as an option at all.

3. **A mandatory unit test template for mutating endpoints**: for every model with a public
   create/update endpoint, a standing "mass-assignment guard" test that submits the endpoint's payload with
   every guarded field present and asserts none of them changed. This turns "did the fillable list leak a
   sensitive field" from a code-review judgment call into a red CI check that fails on this exact patch.

4. **Route the diff through the same SAST/IaC gates regardless of who or what authored it.** This patch
   should never have reached "a junior approved it" as its only gate — an agent-authored security fix should
   run through the identical Semgrep/Larastan pipeline any other PR does, and a PR whose stated purpose is
   "fix a security issue" should be required to link back to the specific finding/scanner rule ID it closes,
   so CI (or a reviewer) can verify the diff actually touches every location that rule flagged — not just
   the first one.

5. **CODEOWNERS-gate anything touching `$fillable`/`$guarded` or `Controllers/Api/*` authorization logic**
   to a security-trained reviewer, independent of general code review — this is exactly the category where
   "looks right to a fast reviewer" is a known failure mode, agent-authored or not, and it's cheap to route
   only this narrow slice of changes through an extra pair of eyes rather than slowing down every PR.

Put together: the goal isn't "review AI output more carefully" as a matter of individual diligence — it's
building the same mechanical gates you'd want for human-authored code, and trusting that agents (like
humans) will reliably produce the failure mode of "fixed the part that was easy to pattern-match, missed or
worsened the part that required understanding the business logic."
