<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

/**
 * Automatic algorithm-based value generator
 */
trait Algorithm
{
    protected static string $name;

    /**
     * @inheritdoc
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
