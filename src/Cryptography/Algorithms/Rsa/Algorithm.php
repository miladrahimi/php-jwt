<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

/**
 * Resolves algorithm-specific values (name, OpenSSL algorithm) from the
 * JWA name.
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
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ][$this->name()];
    }
}
