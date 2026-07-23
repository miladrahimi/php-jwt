<?php

declare(strict_types=1);

/**
 * ES512 — ECDSA over P-521 with SHA-512 (asymmetric: private signs, public verifies).
 *
 * Run:  php examples/es512.php
 */

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Keys — swap these for your own. Each accepts a file path OR an inline PEM string.
$privateKey = new EcdsaPrivateKey(__DIR__ . '/../assets/keys/ecdsa512-private.pem');
$publicKey  = new EcdsaPublicKey(__DIR__ . '/../assets/keys/ecdsa512-public.pem');

// 2) Sign with the private key.
$signer = new ES512Signer($privateKey);
$jwt = (new Generator($signer))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify with the public key.
$verifier = new ES512Verifier($publicKey);
$claims = (new Parser($verifier))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
