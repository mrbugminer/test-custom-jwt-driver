<?php

declare(strict_types=1);

namespace App\JWTDriver;

use App\JWT\JWT;
use App\JWTDriver\Exceptions\GenerateUserTokensException;
use App\Models\User;
use Carbon\Carbon;
use Throwable;

final class JWTDriver
{
    /**
     * @throws GenerateUserTokensException
     */
    public function generateUserTokens(User $user): array
    {
        try {
            $subject = (int)$user->getAuthIdentifier();

            $jwt = new JWT();

            $accessTokenTimeToLive = (int)config('jwt-driver.access_token_ttl', 0);
            if ($accessTokenTimeToLive < 1) {
                throw new GenerateUserTokensException('Access Token Time To Live Must Be Positive');
            }
            $accessToken = Carbon::now('UTC')->format('Ymd-His-u-') . random_int(1000000, 9999999);
            $accessTokenExpirationTime = Carbon::now('UTC')->addMinutes($accessTokenTimeToLive);
            $accessTokenJWT = $jwt->generate(
                subject: $subject,
                expirationTime: $accessTokenExpirationTime,
                customClaims: [
                    'access_token' => $accessToken,
                ]
            );

            $refreshTokenTimeToLive = (int)config('jwt-driver.refresh_token_ttl', 0);
            if ($refreshTokenTimeToLive < 1) {
                throw new GenerateUserTokensException('Refresh Token Time To Live Must Be Positive');
            }
            $refreshToken = Carbon::now('UTC')->format('Ymd-His-u-') . random_int(1000000, 9999999);
            $refreshTokenExpirationTime = Carbon::now('UTC')->addMinutes($refreshTokenTimeToLive);
            $refreshTokenJWT = $jwt->generate(
                subject: $subject,
                expirationTime: $refreshTokenExpirationTime,
                customClaims: [
                    'access_token' => $accessToken,
                    'refresh_token' => $refreshToken,
                ]
            );

            JWTModel::query()->create([
                'user_id' => $subject,
                'access_token' => $accessToken,
                'access_token_expired_at' => $accessTokenExpirationTime,
                'refresh_token' => $refreshToken,
                'refresh_token_expired_at' => $refreshTokenExpirationTime,
            ]);

            return [
                'access_token' => $accessTokenJWT,
                'access_token_ttl' => $accessTokenTimeToLive,
                'refresh_token' => $refreshTokenJWT,
                'refresh_token_ttl' => $refreshTokenTimeToLive,
            ];
        } catch (GenerateUserTokensException $exception) {
            throw $exception;
        } catch (Throwable $throwable) {
            throw new GenerateUserTokensException($throwable->getMessage(), (int)$throwable->getCode(), $throwable);
        }
    }
}
