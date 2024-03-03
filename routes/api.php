<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

Route::prefix('auth')->controller(AuthController::class)->group(function () {

    Route::post('login', 'login')->name('auth.login');

    // Access Token Based
    Route::middleware(['auth:jwt_access_token'])->group(function () {

        Route::get('logout', 'logout')->name('auth.logout');

        Route::get('user', 'user')->name('auth.user');

    });

    // Refresh Token Based
    Route::middleware(['auth:jwt_refresh_token'])->group(function () {

        Route::get('refresh', 'refresh')->name('auth.refresh');

    });

});
