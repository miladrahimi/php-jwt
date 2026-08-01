<?php

/**
 * Ed448 — EdDSA over Curve448, RFC 9864 (asymmetric: private signs, public verifies).
 * Requires PHP 8.4+ with OpenSSL Ed448 support.
 *
 * Generate keys:
 *   openssl genpkey -algorithm ED448 -out ed448-private.pem
 *   openssl pkey -in ed448-private.pem -pubout -out ed448-public.pem
 *
 * Run:  php examples/ed448.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Keys — swap these for your own (PEM file path or inline PEM content).
$privateKey = new Ed448PrivateKey(__DIR__ . '/../assets/keys/ed448-private.pem');
$publicKey  = new Ed448PublicKey(__DIR__ . '/../assets/keys/ed448-public.pem');

// 2) Sign with the private key.
$signer = new Ed448Signer($privateKey);
$jwt = (new Generator($signer))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify with the public key.
$verifier = new Ed448Verifier($publicKey);
$claims = (new Parser($verifier))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
