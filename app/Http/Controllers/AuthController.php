<?php

namespace App\Http\Controllers;

use App\Http\Requests\LoginRequest;
use App\Http\Resources\JWTResource;
use App\Http\Resources\UserResource;
use App\JWTDriver\Exceptions\GenerateUserTokensException;
use App\JWTDriver\JWTDriver;
use App\JWTDriver\JWTModel;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    /**
     * @throws GenerateUserTokensException
     */
    public function login(LoginRequest $request): JWTResource
    {
        $tokens = [];
        if (Auth::guard('jwt_access_token')->attempt($request->validated())) {
            /** @var User $user */
            $user = Auth::guard('jwt_access_token')->user();
            $tokens = (new JWTDriver())->generateUserTokens($user);
        }
        return new JWTResource($tokens);
    }

    public function logout(): JsonResponse
    {
        /** @var JWTModel $jwt */
        $jwt = config('_user_token_');
        $jwt->delete();
        return response()->json();
    }

    public function user(): UserResource
    {
        return new UserResource(
            Auth::guard('jwt_access_token')->user()
        );
    }

    /**
     * @throws GenerateUserTokensException
     */
    public function refresh(): JWTResource
    {
        /** @var JWTModel $jwt */
        $jwt = config('_user_token_');
        $jwtDriver = new JWTDriver();
        $tokens = $jwtDriver->generateUserTokens($jwt->user);
        $jwt->delete();
        return new JWTResource($tokens);
    }
}
