<?php declare(strict_types=1);

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
     * Sign the message
     *
     * @throws SigningException
     */
    public function sign(string $message): string;
}
