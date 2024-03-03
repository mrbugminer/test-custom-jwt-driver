<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        User::query()->create([
            'name' => 'User 1',
            'email' => '1@1.com',
            'password' => Hash::make('111111'),
        ]);
        User::query()->create([
            'name' => 'User 2',
            'email' => '2@2.com',
            'password' => Hash::make('222222'),
        ]);
        User::query()->create([
            'name' => 'User 3',
            'email' => '3@3.com',
            'password' => Hash::make('333333'),
        ]);
    }
}
