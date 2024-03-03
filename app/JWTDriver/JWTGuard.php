<?php

declare(strict_types=1);

namespace App\JWTDriver;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

final class JWTGuard implements Guard
{
    use GuardHelpers;

    public function __construct(
        UserProvider $provider,
        private readonly Request $request,
    ) {
        $this->setProvider($provider);
    }

    public function user(): Authenticatable|null
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $user = null;

        $token = trim($this->request->bearerToken() ?? '');
        if ($token !== '') {
            $user = $this->getProvider()->retrieveByToken('', $token);
        }

        $this->user = $user;

        return $user;
    }

    public function validate(array $credentials = []): bool
    {
        return $this->getProvider()->retrieveByCredentials($credentials) !== null;
    }

    public function attempt(array $credentials = []): Authenticatable|null
    {
        $user = $this->getProvider()->retrieveByCredentials($credentials);

        $this->user = $user;

        return $user;
    }
}
