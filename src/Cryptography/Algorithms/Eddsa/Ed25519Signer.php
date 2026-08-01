<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

/**
 * Signs tokens with `Ed25519`, the RFC 9864 fully-specified name for EdDSA over Curve25519. It produces the
 * same signatures as `EdDsaSigner`; only the JWS `alg` header value differs.
 */
class Ed25519Signer extends EdDsaSigner
{
    protected static string $name = 'Ed25519';
}
