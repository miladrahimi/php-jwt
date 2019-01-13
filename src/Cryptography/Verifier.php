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
     * @param string $header
     * @param string $payload
     * @param string $signature
     * @throws InvalidSignatureException
     */
    public function verify(string $header, string $payload, string $signature);
}
