<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography;

/**
 * A verifier that exposes its algorithm (JWS `alg`) name, allowing the parser to reject tokens whose declared
 * algorithm contradicts it. All built-in verifiers implement it; custom verifiers opt in by implementing it too.
 */
interface NamedVerifier extends Verifier
{
    /**
     * Returns the verifier (algorithm) name.
     */
    public function name(): string;
}
