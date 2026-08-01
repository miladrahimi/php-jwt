<?php

/**
 * Ed25519 — the RFC 9864 fully-specified name for EdDSA over Curve25519 (asymmetric: private signs, public
 * verifies). Requires ext-sodium.
 *
 * Run:  php examples/ed25519.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Keys — swap these for your own (raw Ed25519 key bytes, same keys as EdDSA).
//    The sample key files store the bytes base64-encoded, so they are decoded here.
$privateKey = new EdDsaPrivateKey(base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.sec')));
$publicKey  = new EdDsaPublicKey(base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.pub')));

// 2) Sign with the private key.
$signer = new Ed25519Signer($privateKey);
$jwt = (new Generator($signer))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify with the public key.
$verifier = new Ed25519Verifier($publicKey);
$claims = (new Parser($verifier))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
