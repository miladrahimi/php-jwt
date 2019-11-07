<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class TestCase extends \MiladRahimi\Jwt\Tests\TestCase
{
    /**
     * @var PublicKey
     */
    protected $publicKey;

    /**
     * @var PrivateKey
     */
    protected $privateKey;

    /**
     * @return PrivateKey
     * @throws InvalidKeyException
     */
    protected function privateKey(): PrivateKey
    {
        return $this->privateKey ?:
            $this->privateKey = new PrivateKey(__DIR__ . '/../../../../resources/test/keys/private.pem');
    }

    /**
     * @return PublicKey
     * @throws InvalidKeyException
     */
    protected function publicKey(): PublicKey
    {
        return $this->publicKey ?:
            $this->publicKey = new PublicKey(__DIR__ . '/../../../../resources/test/keys/public.pem');
    }
}
