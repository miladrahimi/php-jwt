<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class HmacKey
{
    private string $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * @throws InvalidKeyException
     */
    public static function create(string $key): HmacKey
    {
        if (strlen($key) < 32 || strlen($key) > 6144) {
            throw new InvalidKeyException('Key length must be between 32 and 6144');
        }

        return new HmacKey($key);
    }

    public function __toString(): string
    {
        return $this->key;
    }
}