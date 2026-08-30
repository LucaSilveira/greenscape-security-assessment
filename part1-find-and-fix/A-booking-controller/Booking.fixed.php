<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Booking extends Model
{
    // Explicit deny-list beats an incomplete allow-list: whatever new column gets added next
    // (by a human or an agent) is guarded by default instead of silently mass-assignable.
    protected $guarded = [
        'id',
        'customer_id',
        'pro_id',
        'pro_payout_cents',
        'status',
        'card_last4',
        'created_at',
        'updated_at',
    ];

    public function customer()
    {
        return $this->belongsTo(Customer::class);
    }
}
