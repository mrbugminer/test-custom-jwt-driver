<?php

return [

    // Access Token Time To Live ( In Minutes )
    'access_token_ttl' => (int)env('ACCESS_TOKEN_TTL', 3),

    // Refresh Token Time To Live ( In Minutes )
    'refresh_token_ttl' => (int)env('REFRESH_TOKEN_TTL', 7),

];
