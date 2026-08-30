# Artifact A — `app/Http/Controllers/Api/BookingController.php` (Laravel)

Three distinct findings in ~35 lines. Route file adds no additional authorization beyond `auth:sanctum`
(any valid customer or pro session), so every finding below is reachable by any authenticated user.

## Finding A1 — IDOR / Broken Object-Level Authorization in `show()`

**Vulnerability class:** Broken Access Control — IDOR / BOLA (OWASP API1:2023).

**Exploit path:** `Booking::findOrFail($id)` performs no ownership check. `$id` is a sequential/enumerable
primary key. Any authenticated customer or pro can call `GET /api/v2/bookings/{id}` with an ID that isn't
theirs and receive another customer's full name, email, phone, home address, card last-4, and the pro's
payout amount for that job. Attacker is a $0-cost registered account (customer or pro); impact is bulk
harvesting of customer PII and pro financial data by simply iterating IDs — no rate limiting is defined on
the route.

**Severity: High.** Not "Critical" only because card data is limited to last-4 (not full PAN) here — but this
is a marketplace with ~$100M/yr in bookings; an attacker can script a scrape of the entire `bookings` table's
customer contact info and pro earnings in an afternoon. That's an LGPD/PII incident and a pro-trust problem
(pros will notice their payouts are visible to random customers) even before you get to fraud.

**Fix:** scope to the caller and stop returning data the caller has no business seeing (pro payout is not the
customer's data — see systemic note).

```diff
-    public function show($id)
+    public function show(Request $request, $id)
     {
-        $booking = Booking::findOrFail($id);
+        $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);
         return response()->json([
             'id' => $booking->id,
             'address' => $booking->address,
             'customer' => $booking->customer->only(['name', 'email', 'phone']),
-            'pro_payout' => $booking->pro_payout_cents,
             'card_last4' => $booking->card_last4,
         ]);
     }
```

If pros also need to hit a "show" endpoint for their own bookings (to see the payout), that should be a
**separate** route/controller method authorizing against `pro_id`, not the same response shape reused for
both audiences. One serializer shared across two trust levels is how payout data ends up in the customer
response in the first place.

## Finding A2 — SQL Injection in `search()`

**Vulnerability class:** Injection — CWE-89 (SQL Injection).

**Exploit path:** `$zip` and `$status` are concatenated directly into a raw SQL string executed via
`DB::select()`. Any authenticated user controls both query params. Classic UNION-based or boolean-blind
extraction gives read access to the entire Postgres database from an app-tier account — that's customer
PII, pro banking/payout tables, and payment metadata, not just the `bookings` table. Depending on the DB
user's grants, this can extend to data modification. This is the single worst finding in this artifact:
authenticated-but-cheap access → full database compromise.

**Severity: Critical.** Direct, unauthenticated-relative-to-data path to the entire customer/pro/payment
dataset. In a marketplace processing card payments, this is a reportable breach waiting to happen.

**Fix:** use the query builder (auto-parameterized) and validate `status` against an allow-list instead of
interpolating it:

```php
public function search(Request $request)
{
    $validated = $request->validate([
        'zip'    => ['required', 'regex:/^\d{5}(-\d{4})?$/'],
        'status' => ['sometimes', Rule::in(['active', 'completed', 'cancelled', 'pending'])],
    ]);

    $rows = Booking::query()
        ->where('customer_id', $request->user()->id) // see Finding A3 below — this was missing entirely
        ->where('zip', $validated['zip'])
        ->where('status', $validated['status'] ?? 'active')
        ->orderByDesc('scheduled_for')
        ->get(['id', 'address', 'scheduled_for', 'status']);

    return response()->json($rows);
}
```

## Finding A3 — Missing authorization scope in `search()` (separate from the injection)

Even with the SQLi fixed, the original query has **no `customer_id`/`pro_id` filter at all** — it searches
`bookings` across every customer in the system by zip code. That's a second, independent BOLA: a customer
can already see every other customer's address, schedule, and status in their zip code without any
injection required, just by hitting `/bookings/search?zip=<their neighborhood>`. This is called out
separately from A2 because a scanner or a fast fix of the SQLi alone (see Part 1B) will not catch it — it's
a data-model/business-logic gap, not a syntax bug. Fixed in the snippet above by scoping to
`$request->user()->id`. If `search` is meant to be an internal/ops tool rather than customer-facing, it
should not be behind `auth:sanctum` for arbitrary users at all — it should require a staff policy/role.

## Finding A4 — Mass assignment risk in `update()`

**Vulnerability class:** Improper Authorization via Mass Assignment (CWE-915).

`update()` does correctly scope the lookup to `customer_id`, but then calls
`$booking->update($request->all())`. As shipped in Artifact A, `Booking` has no `$fillable`/`$guarded`
declared, so Eloquent's default guard-everything behavior likely no-ops this — but that's fragile, not a
control. The moment anyone (human or agent) adds a `$fillable` array to make the endpoint "work" without
naming the exact safe fields, this becomes exploitable (this is exactly what happens in Part 1B: an
agent's patch adds `pro_payout_cents` and `customer_id` to `$fillable`, turning this dormant risk into a live
one). Treat it as a finding now rather than waiting to be bitten by it.

**Fix:** whitelist via a `FormRequest`, never `$request->all()`, and set `$guarded` explicitly on the model.
`$guarded` only gates mass-assignment (what can be written), not serialization (what gets read back) — the
two are independent controls, and it's easy to fix one and assume it covers the other. Returning `$booking`
directly after the update would re-serialize `pro_payout_cents`, `card_last4`, `customer_id`, and `pro_id`
into the response, undoing A1's fix to `show()` for the same reason A1 needed fixing in the first place:

```php
public function update(UpdateBookingRequest $request, $id)
{
    $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);
    $booking->update($request->validated()); // FormRequest only allows customer-editable fields

    return response()->json([
        'id' => $booking->id,
        'address' => $booking->address,
        'scheduled_for' => $booking->scheduled_for,
        'status' => $booking->status,
    ]); // explicit shape, not $booking directly — same reasoning as A1's response fix
}
```

```php
// app/Models/Booking.php
protected $guarded = ['id', 'customer_id', 'pro_id', 'pro_payout_cents', 'status', 'card_last4', 'created_at', 'updated_at'];
```

## Severity summary

| # | Issue | Class | Severity | Who's exploited / what's taken |
|---|-------|-------|----------|---------------------------------|
| A1 | IDOR in `show()` | Broken Access Control | High | Any customer's PII + pro payout, scriptable at scale |
| A2 | SQLi in `search()` | Injection | Critical | Full DB read (PII, banking, payments), possible write |
| A3 | No authz scope in `search()` | Broken Access Control | High | Every customer's address/schedule in a zip, no injection needed |
| A4 | Mass assignment in `update()` | Improper Authorization | High (latent → live once `$fillable` is touched) | Booking hijack, payout tampering, status forgery |

## What I'd clear, not flag

`update()`'s ownership check (`where('customer_id', auth()->id())`) is correct as written and is the pattern
the *other* two methods should have copied — it's evidence the team knows the right idiom, they just didn't
apply it consistently. Not every method needed a rewrite; `update()`'s lookup line ships as-is.

## Systemic control (kills the class, not the instance)

This isn't "three unlucky lines" — it's the same two patterns (no ownership scope on a fetch-by-ID, raw SQL
string interpolation) that will recur anywhere an agent or engineer adds a new endpoint under time pressure.
The control that scales:

1. **Ban raw interpolated SQL org-wide.** A Semgrep rule (`p/php` + a custom rule matching
   `DB::(select|statement)\(\s*"[^"]*\$` or `->whereRaw\(.*\$`) in CI, blocking merge. This is exactly the
   class of bug a SAST tool is deterministic at catching — pattern-match on string interpolation reaching a
   SQL sink — and it's cheap to run on every PR, including agent-authored ones.
2. **Require Policies, not inline `where()` clauses, for every Eloquent model exposed via API.** A Laravel
   Policy (`Gate::authorize('view', $booking)`) is one auditable place to look, instead of trusting every
   controller method to remember to add the same `where('customer_id', ...)` by hand. Add a CI check (or a
   Larastan custom rule) that any `Route::` entry under `Api/` maps to a controller method that calls
   `authorize()`/`can()` before touching the model, or is explicitly annotated as intentionally public.
3. **Ban `$request->all()` in `->update()`/`->create()`/`->fill()` calls.** Another Semgrep rule; require
   `FormRequest::validated()`. This also forces someone to think about `$fillable` per field instead of
   reaching for "just make it fillable" the way the agent did in Part 1B.
4. **A scanner would reliably catch:** the raw-SQL interpolation (A2) and probably the missing FormRequest
   pattern (A4) — both are syntactic. **A scanner would not catch:** A1 and A3, because those require
   knowing that `bookings.customer_id` is the ownership boundary for this business domain — that's a
   business-logic/BOLA gap, and it's exactly the kind of thing a human reviewer (or a policy-per-model
   convention, see #2) has to supply.
