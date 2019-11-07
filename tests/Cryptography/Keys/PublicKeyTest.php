<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;

class PublicKeyTest extends TestCase
{
    public function test_with_valid_key_it_should_pass()
    {
        $key = new PublicKey(__DIR__ . '/../../../resources/test/keys/public.pem');
        $this->assertNotNull($key->getResource());
    }

    public function test_with_invalid_key_it_should_fail()
    {
        $this->expectException(InvalidKeyException::class);
        new PublicKey('Invalid');
    }
}
