<?php

declare(strict_types=1);

namespace App\JWTDriver;

use App\JWT\JWT;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Throwable;

final class JWTUserProvider implements UserProvider
{

    public function __construct(
        private readonly string $tokenType,
    ) {
    }

    public function retrieveById($identifier): Authenticatable|null
    {
        /** @var Authenticatable|null $user */
        $user = User::query()->find($identifier);

        return $user;
    }

    public function retrieveByToken($identifier, $token): Authenticatable|null
    {
        $now = Carbon::now('UTC');

        try {
            $jwt = (new JWT())->parse($token);

            if ($jwt['expiration_time'] <= $now) {
                return null;
            }
        } catch (Throwable) {
            return null;
        }

        /** @var JWTModel|null $jwtModel */
        $jwtModel = null;

        if ($this->tokenType === 'jwt_access_token') {

            if (!array_key_exists('access_token', $jwt)) {
                return null;
            }
            $jwtModel = JWTModel::query()
                ->with(['user'])
                ->where('user_id', '=', $jwt['subject'])
                ->where('access_token', '=', trim($jwt['access_token'] ?? ''))
                ->where('access_token_expired_at', '>', $now)
                ->first();

        } else if ($this->tokenType === 'jwt_refresh_token') {

            if (!array_key_exists('access_token', $jwt) || !array_key_exists('refresh_token', $jwt)) {
                return null;
            }
            $jwtModel = JWTModel::query()
                ->with(['user'])
                ->where('user_id', '=', $jwt['subject'])
                ->where('access_token', '=', trim($jwt['access_token'] ?? ''))
                ->where('refresh_token', '=', trim($jwt['refresh_token'] ?? ''))
                ->where('refresh_token_expired_at', '>', $now)
                ->first();

        }

        if ($jwtModel === null) {
            return null;
        }

        /** @var Authenticatable|null $user */
        $user = $jwtModel->user;
        if ($user === null) {
            return null;
        }

        config(['_user_token_' => $jwtModel]);

        return $user;
    }

    public function updateRememberToken(Authenticatable $user, $token): void
    {
    }

    public function retrieveByCredentials(array $credentials): Authenticatable|null
    {
        if (!array_key_exists('email', $credentials)) {
            return null;
        }

        $email = trim($credentials['email']);
        if ($email === '') {
            return null;
        }

        /** @var Authenticatable|null $user */
        $user = User::query()
            ->where('email', '=', $email)
            ->first();

        return $user;
    }

    public function validateCredentials(Authenticatable $user, array $credentials): bool
    {
        if (!array_key_exists('password', $credentials)) {
            return false;
        }

        $password = trim($credentials['password']);
        if ($password === '') {
            return false;
        }

        return app('hash')->check($password, $user->getAuthPassword());
    }
}
