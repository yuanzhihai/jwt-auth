<?php

return [
    /*
    |--------------------------------------------------------------------------
    | JWT Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this in your .env file, as it will be used to sign
    | your tokens. A helper command is provided for this:
    | `php artisan jwt:secret`
    |
    | Note: This will be used for Symmetric algorithms only (HMAC),
    | since RSA and ECDSA use a private/public key combo (See below).
    |
    */

    'secret'                 => env('JWT_SECRET'),
    /*
   |--------------------------------------------------------------------------
   | JWT Authentication Keys
   |--------------------------------------------------------------------------
   |
   | The algorithm you are using, will determine whether your tokens are
   | signed with a random string (defined in `JWT_SECRET`) or using the
   | following public & private keys.
   |
   | Symmetric Algorithms:
   | HS256, HS384 & HS512 will use `JWT_SECRET`.
   |
   | Asymmetric Algorithms:
   | RS256, RS384 & RS512 / ES256, ES384 & ES512 will use the keys below.
   |
   */
    'keys'                   => [
        /*
       |--------------------------------------------------------------------------
       | Public Key
       |--------------------------------------------------------------------------
       |
       | A path or resource to your public key.
       |
       | E.g. 'file://path/to/public/key'
       |
       */
        'public_key'  => env('JWT_PUBLIC_KEY'),
        /*
        |--------------------------------------------------------------------------
        | Private Key
        |--------------------------------------------------------------------------
        |
        | A path or resource to your private key.
        |
        | E.g. 'file://path/to/private/key'
        |
        */
        'private_key' => env('JWT_PRIVATE_KEY'),
        /*
        |--------------------------------------------------------------------------
        | Passphrase
        |--------------------------------------------------------------------------
        |
        | The passphrase for your private key. Can be null if none set.
        |
        */
        'passphrase'  => env('JWT_PASSPHRASE'),
    ],
    /*
    |--------------------------------------------------------------------------
    | JWT time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
    | Defaults to 1 hour.
    |
    | You can also set this to null, to yield a never expiring token.
    | Some people may want this behaviour for e.g. a mobile app.
    | This is not particularly recommended, so make sure you have appropriate
    | systems in place to revoke the token if necessary.
    | Notice: If you set this to null you should remove 'exp' element from 'required_claims' list.
    |
    */
    'ttl'                    => env('JWT_TTL', 600),
    /*
    |--------------------------------------------------------------------------
    | Refresh time to live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token can be refreshed
    | within. I.E. The user can refresh their token within a 2 week window of
    | the original token being created until they must re-authenticate.
    | Defaults to 2 weeks.
    |
    | You can also set this to null, to yield an infinite refresh time.
    | Some may want this instead of never expiring tokens for e.g. a mobile app.
    | This is not particularly recommended, so make sure you have appropriate
    | systems in place to revoke the token if necessary.
    |
    */
    'refresh_ttl'            => env('JWT_REFRESH_TTL', 20160),

    /*
    |--------------------------------------------------------------------------
    | JWT hashing algorithm
    |--------------------------------------------------------------------------
    |
    | Specify the hashing algorithm that will be used to sign the token.
    |
    | See here: https://github.com/namshi/jose/tree/master/src/Namshi/JOSE/Signer/OpenSSL
    | for possible values.
    |
    */
    'algo'                   => env('JWT_ALGO', 'HS256'),
    /*
      |--------------------------------------------------------------------------
      | Leeway
      |--------------------------------------------------------------------------
      |
      | This property gives the jwt timestamp claims some "leeway".
      | Meaning that if you have any unavoidable slight clock skew on
      | any of your servers then this will afford you some level of cushioning.
      |
      | This applies to the claims `iat`, `nbf` and `exp`.
      |
      | Specify in seconds - only if you know you need it.
      |
     */
    'leeway'                 => env('JWT_LEEWAY', 0),
    /*
    |--------------------------------------------------------------------------
    | Required Claims
    |--------------------------------------------------------------------------
    |
    | Specify the required claims that must exist in any token.
    | A TokenInvalidException will be thrown if any of these claims are not
    | present in the payload.
    |
    */
    'required_claims'        => [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
        'aud',
    ],
    //token获取方式，数组靠前值优先
    'token_mode'             => ['header', 'cookie', 'param'],
    /*
    | -------------------------------------------------------------------------
    | Blacklist Grace Period
    | -------------------------------------------------------------------------
    |
    | When multiple concurrent requests are made with the same JWT,
    | it is possible that some of them fail, due to token regeneration
    | on every request.
    |
    | Set grace period in seconds to prevent parallel request failure.
    |
    */
    'blacklist_grace_period' => env('BLACKLIST_GRACE_PERIOD', 10),
    /*
     |--------------------------------------------------------------------------
     | Storage Provider
     |--------------------------------------------------------------------------
     |
     | Specify the provider that is used to store tokens in the blacklist.
     |
     */
    'blacklist_storage'      => thans\jwt\provider\storage\Tp6::class,
];
