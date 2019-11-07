<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;

class PrivateKeyTest extends TestCase
{
    public function test_with_valid_key_it_should_pass()
    {
        $key = new PrivateKey(__DIR__ . '/../../../resources/test/keys/private.pem');
        $this->assertNotNull($key->getResource());
    }

    public function test_with_invalid_key_it_should_fail()
    {
        $this->expectException(InvalidKeyException::class);
        new PrivateKey('Invalid');
    }
}
