<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * It employs cryptographic algorithms to verify messages, serving as
 * the mechanism for verifying the signature in JSON Web Tokens (JWTs).
 */
interface Verifier
{
    /**
     * Verify JWT signature
     *
     * @throws InvalidSignatureException
     * @throws SigningException
     */
    public function verify(string $plain, string $signature): void;

    /**
     * Retrieve the kid (Key ID)
     *
     * @return string|null It returns null if no kid is specified and a string if a key is specified.
     */
    public function kid(): ?string;
}
