<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * It employs cryptographic algorithms to sign messages, serving as
 * the mechanism for generating the signature in JSON Web Tokens (JWTs).
 */
interface Signer
{
    /**
     * Retrieve the signer name
     */
    public function name(): string;

    /**
     * Retrieve the kid (Key ID)
     *
     * @return string|null It returns null if no kid is specified and a string if a key is specified.
     */
    public function kid(): ?string;

    /**
     * Sign the message
     *
     * @throws SigningException
     */
    public function sign(string $message): string;
}
