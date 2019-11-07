<?php

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

/**
 * Interface Verifier
 *
 * @package MiladRahimi\Jwt\Cryptography
 */
interface Verifier
{
    /**
     * Verify token signature
     *
     * @param string $plain
     * @param string $signature
     * @throws InvalidSignatureException
     */
    public function verify(string $plain, string $signature);
}
