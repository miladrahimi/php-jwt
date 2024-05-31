<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class RsaPrivateKeyTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_with_valid_key_file_it_should_pass()
    {
        $key = new RsaPrivateKey(__DIR__ . '/../../../assets/keys/rsa-private.pem');
        $this->assertNotNull($key->getResource());
    }

    /**
     * @throws Throwable
     */
    public function test_with_valid_key_string_it_should_pass()
    {
        $key = new RsaPrivateKey(file_get_contents(__DIR__ . '/../../../assets/keys/rsa-private.pem'));
        $this->assertNotNull($key->getResource());
    }

    /**
     * @throws Throwable
     */
    public function test_id()
    {
        $key = new RsaPrivateKey(__DIR__ . '/../../../assets/keys/rsa-private.pem', '', 'id-1');
        $this->assertEquals('id-1', $key->getId());
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_path_it_should_fail()
    {
        $this->expectException(InvalidKeyException::class);
        new RsaPrivateKey('Invalid Key!');
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_file_it_should_fail()
    {
        $this->expectException(InvalidKeyException::class);
        new RsaPrivateKey(__DIR__ . '/../../../assets/file.empty');
    }
}
