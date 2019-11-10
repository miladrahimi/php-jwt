<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class PrivateKeyTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_with_valid_key_it_should_pass()
    {
        $key = new PrivateKey(__DIR__ . '/../../../resources/test/keys/rsa-private.pem');
        $this->assertNotNull($key->getResource());
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_it_should_fail()
    {
        $this->expectException(InvalidKeyException::class);
        new PrivateKey('Invalid Key!');
    }
}
