<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class TestCase extends \MiladRahimi\Jwt\Tests\TestCase
{
    /**
     * @return PrivateKey
     * @throws InvalidKeyException
     */
    protected function privateKey(): PrivateKey
    {
        return new PrivateKey(__DIR__ . '/../../../../resources/test/keys/private.pem');
    }

    /**
     * @return PublicKey
     * @throws InvalidKeyException
     */
    protected function publicKey(): PublicKey
    {
        return new PublicKey(__DIR__ . '/../../../../resources/test/keys/public.pem');
    }
}
