<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class EdDsaPublicKeyTest extends TestCase
{
    private const PATH = __DIR__ . '/../../../assets/keys/ed25519.pub';
    /**
     * @throws Throwable
     */
    public function test_with_valid_key_it_should_pass()
    {
        $key = new EdDsaPublicKey(base64_decode(file_get_contents(self::PATH)));
        $this->assertNotNull($key->getContent());
    }

    /**
     * @throws Throwable
     */
    public function test_id()
    {
        $key = new EdDsaPrivateKey(base64_decode(file_get_contents(self::PATH)), 'id-1');
        $this->assertEquals('id-1', $key->getId());
    }
}
