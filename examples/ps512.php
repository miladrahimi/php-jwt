<?php

/**
 * PS512 — RSA-PSS with SHA-512 (asymmetric: private key signs, public key verifies).
 *
 * Run:  php examples/ps512.php
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;

// 1) Keys — swap these for your own. PS* uses ordinary RSA keys; each accepts a file path OR an inline PEM.
$privateKey = new RsaPrivateKey(__DIR__ . '/../assets/keys/rsa-private.pem');
$publicKey  = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem');

// 2) Sign with the private key.
$signer = new PS512Signer($privateKey);
$jwt = (new Generator($signer))->generate([
    'sub'  => '42',
    'name' => 'Pink Floyd',
]);
echo "Token:\n{$jwt}\n\n";

// 3) Verify with the public key.
$verifier = new PS512Verifier($publicKey);
$claims = (new Parser($verifier))->parse($jwt);
echo "Verified claims:\n";
print_r($claims);
