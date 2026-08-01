<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

/**
 * Verifies tokens signed with `Ed25519`, the RFC 9864 fully-specified name for EdDSA over Curve25519. It
 * accepts the same signatures as `EdDsaVerifier`; only the JWS `alg` header value differs.
 */
class Ed25519Verifier extends EdDsaVerifier
{
    protected static string $name = 'Ed25519';
}
