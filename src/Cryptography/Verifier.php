<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Employs cryptographic algorithms to verify messages, checking the
 * signature of JSON Web Tokens (JWTs).
 */
interface Verifier
{
    /**
     * Verifies the JWT signature.
     *
     * @throws InvalidSignatureException
     * @throws SigningException
     */
    public function verify(string $plain, string $signature): void;

    /**
     * Returns the key ID (kid).
     *
     * @return string|null The key ID, or null when none is specified.
     */
    public function kid(): ?string;
}
