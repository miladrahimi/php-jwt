<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:13
 */

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

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