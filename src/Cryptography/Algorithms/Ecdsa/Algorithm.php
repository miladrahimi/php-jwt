<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

/**
 * Resolves algorithm-specific values (name, OpenSSL algorithm, coordinate size)
 * from the JWA name.
 */
trait Algorithm
{
    protected static string $name;

    /**
     * {@inheritDoc}
     */
    public function name(): string
    {
        return static::$name;
    }

    protected function algorithm(): int
    {
        return [
            'ES256' => OPENSSL_ALGO_SHA256,
            'ES256K' => OPENSSL_ALGO_SHA256,
            'ES384' => OPENSSL_ALGO_SHA384,
            'ES512' => OPENSSL_ALGO_SHA512,
        ][$this->name()];
    }

    /**
     * Returns the byte length of one signature coordinate (r or s): the curve size in bits rounded up to whole
     * bytes — P-521 does not divide evenly, so ES512 uses 66 bytes, not 64 (RFC 7518 §3.4).
     */
    protected function coordinateSize(): int
    {
        return [
            'ES256' => 32,
            'ES256K' => 32,
            'ES384' => 48,
            'ES512' => 66,
        ][static::$name];
    }
}
