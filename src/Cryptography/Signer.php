<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Employs cryptographic algorithms to sign messages, producing the
 * signature of JSON Web Tokens (JWTs).
 */
interface Signer
{
    /**
     * Returns the signer (algorithm) name.
     */
    public function name(): string;

    /**
     * Returns the key ID (kid).
     *
     * @return string|null The key ID, or null when none is specified.
     */
    public function kid(): ?string;

    /**
     * Signs the message.
     *
     * @throws SigningException
     */
    public function sign(string $message): string;
}
