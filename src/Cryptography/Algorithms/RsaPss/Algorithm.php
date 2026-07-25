<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss;

/**
 * Resolves algorithm-specific values (name, hash algorithm) from the
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

    protected function algorithm(): string
    {
        return [
            'PS256' => 'sha256',
            'PS384' => 'sha384',
            'PS512' => 'sha512',
        ][$this->name()];
    }
}
