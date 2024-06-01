<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

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
            'ES256' => OPENSSL_ALGO_SHA256,
            'ES256K' => OPENSSL_ALGO_SHA256,
            'ES384' => OPENSSL_ALGO_SHA512,
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
