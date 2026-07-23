<?php

declare(strict_types=1);

/**
 * RS256 — RSA with SHA-256 (asymmetric: private key signs, public key verifies).
 *
 * Run:  php examples/rs256.php
 */

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Keys — swap these for your own. Each accepts a file path OR an inline PEM string.
$privateKey = new RsaPrivateKey(__DIR__ . '/../assets/keys/rsa-private.pem');
$publicKey  = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem');

// 2) Sign with the private key.
$signer = new RS256Signer($privateKey);
$jwt = (new Generator($signer))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify with the public key.
$verifier = new RS256Verifier($publicKey);
$claims = (new Parser($verifier))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
