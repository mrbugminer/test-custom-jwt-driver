<?php

declare(strict_types=1);

namespace App\JWTDriver;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\SoftDeletes;

class JWTModel extends Model
{
    use SoftDeletes;

    protected $table = 'jwt';

    protected $fillable = [
        'user_id',
        'access_token',
        'access_token_expired_at',
        'refresh_token',
        'refresh_token_expired_at',
    ];

    protected $casts = [
        'user_id' => 'int',
        'access_token' => 'string',
        'access_token_expired_at' => 'datetime',
        'refresh_token' => 'string',
        'refresh_token_expired_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id', 'id');
    }
}
