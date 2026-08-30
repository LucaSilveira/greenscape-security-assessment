<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateBookingRequest;
use App\Models\Booking;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class BookingController extends Controller
{
    // GET /api/v2/bookings/{id}
    // Fix (A1): scope to the caller; do not leak pro payout data into the customer-facing response.
    public function show(Request $request, $id)
    {
        $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);

        return response()->json([
            'id' => $booking->id,
            'address' => $booking->address,
            'customer' => $booking->customer->only(['name', 'email', 'phone']),
            'card_last4' => $booking->card_last4,
        ]);
    }

    // GET /api/v2/bookings/search?zip=...&status=...
    // Fix (A2): parameterized query builder, no raw SQL string interpolation.
    // Fix (A3): scoped to the caller — this was returning every customer's bookings before.
    public function search(Request $request)
    {
        $validated = $request->validate([
            'zip' => ['required', 'regex:/^\d{5}(-\d{4})?$/'],
            'status' => ['sometimes', Rule::in(['active', 'completed', 'cancelled', 'pending'])],
        ]);

        $rows = Booking::query()
            ->where('customer_id', $request->user()->id)
            ->where('zip', $validated['zip'])
            ->where('status', $validated['status'] ?? 'active')
            ->orderByDesc('scheduled_for')
            ->get(['id', 'address', 'scheduled_for', 'status']);

        return response()->json($rows);
    }

    // POST /api/v2/bookings/{id}
    // Fix (A4): FormRequest whitelist instead of $request->all(); model $guarded locks down
    // financial/ownership/status fields regardless of what the request body contains.
    public function update(UpdateBookingRequest $request, $id)
    {
        $booking = Booking::where('customer_id', $request->user()->id)->findOrFail($id);
        $booking->update($request->validated());

        // $guarded only gates mass-assignment, not serialization — returning $booking
        // directly here would re-leak pro_payout_cents/card_last4/customer_id/pro_id,
        // undoing the exact response-shaping fix applied to show() in A1. Same shape,
        // same reasoning: the caller gets back what they're allowed to see, nothing more.
        return response()->json([
            'id' => $booking->id,
            'address' => $booking->address,
            'scheduled_for' => $booking->scheduled_for,
            'status' => $booking->status,
        ]);
    }
}
