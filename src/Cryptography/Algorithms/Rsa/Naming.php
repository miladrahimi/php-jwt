<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

/**
 * Trait Naming
 * Automatic name generator for RSA algorithm classes
 *
 * @package MiladRahimi\Jwt\Cryptography\Algorithms\Rsa
 */
trait Naming
{
    /**
     * @var string  Algorithm name
     */
    protected static $name;

    /**
     * @inheritdoc
     */
    public function name(): string
    {
        return static::$name;
    }

    /**
     * @return int
     */
    protected function algorithm()
    {
        $table = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];

        return $table[$this->name()];
    }
}
