<?php

/**
 * HS384 — HMAC with SHA-384 (symmetric: the same secret signs and verifies).
 *
 * Run:  php examples/hs384.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS384;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Key — swap this secret for your own (any string of 32–6144 characters).
$key = new HmacKey('12345678901234567890123456789012');

// 2) Sign — build a token from your claims.
$hs384 = new HS384($key); // HMAC uses one object as both signer and verifier
$jwt = (new Generator($hs384))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify — check the signature and read the claims back.
$claims = (new Parser($hs384))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
