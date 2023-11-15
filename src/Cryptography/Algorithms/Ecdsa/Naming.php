<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

/**
 * Automatic algorithm name generator
 */
trait Naming
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
            'ES384' => OPENSSL_ALGO_SHA384,
        ][$this->name()];
    }
}
