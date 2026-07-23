<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

/**
 * Resolves algorithm-specific values (name, OpenSSL algorithm, key size)
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
        ][$this->name()];
    }

    protected function keySize(): int
    {
        return [
            'ES256' => 256,
            'ES256K' => 256,
            'ES384' => 384,
        ][static::$name];
    }
}
