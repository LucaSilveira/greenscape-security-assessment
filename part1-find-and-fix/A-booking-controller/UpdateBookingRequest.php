<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

class UpdateBookingRequest extends FormRequest
{
    public function authorize(): bool
    {
        // Ownership is still enforced in the controller via the customer_id-scoped lookup;
        // this only whitelists *fields*, it is not the authorization boundary by itself.
        return true;
    }

    public function rules(): array
    {
        return [
            // Only fields a customer is allowed to change post-booking. Notably absent:
            // status, pro_payout_cents, customer_id, card_last4 — those are guarded on the
            // model (belt and suspenders) and never accepted from this endpoint at all.
            'scheduled_for' => ['sometimes', 'date', 'after:now'],
            'address' => ['sometimes', 'string', 'max:255'],
        ];
    }
}
