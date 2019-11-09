<?php

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;

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
     * @throws SigningException
     */
    public function verify(string $plain, string $signature);
}
