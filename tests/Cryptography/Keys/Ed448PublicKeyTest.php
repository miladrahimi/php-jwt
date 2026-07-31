<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Keys;

use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class Ed448PublicKeyTest extends TestCase
{
    private function requireEd448Support(): void
    {
        if (!defined('OPENSSL_KEYTYPE_ED448')) {
            $this->markTestSkipped('Ed448 keys require PHP 8.4 or later with OpenSSL Ed448 support.');
        }
    }

    /**
     * @throws Throwable
     */
    public function test_with_valid_key_file_it_should_pass()
    {
        $this->requireEd448Support();

        $key = new Ed448PublicKey(__DIR__ . '/../../../assets/keys/ed448-public.pem');
        $this->assertNotNull($key->getResource());
    }

    /**
     * @throws Throwable
     */
    public function test_with_valid_key_string_it_should_pass()
    {
        $this->requireEd448Support();

        $key = new Ed448PublicKey(file_get_contents(__DIR__ . '/../../../assets/keys/ed448-public.pem'));
        $this->assertNotNull($key->getResource());
    }

    /**
     * @throws Throwable
     */
    public function test_id()
    {
        $this->requireEd448Support();

        $key = new Ed448PublicKey(__DIR__ . '/../../../assets/keys/ed448-public.pem', 'id-1');
        $this->assertEquals('id-1', $key->getId());
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_path_it_should_fail()
    {
        $this->requireEd448Support();

        $this->expectException(InvalidKeyException::class);
        new Ed448PublicKey('Invalid Key!');
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_file_it_should_fail()
    {
        $this->requireEd448Support();

        $this->expectException(InvalidKeyException::class);
        new Ed448PublicKey(__DIR__ . '/../../../assets/file.empty');
    }

    /**
     * The exception carries the underlying OpenSSL error explaining why the key was rejected.
     *
     * @throws Throwable
     */
    public function test_with_invalid_key_it_should_carry_the_openssl_error()
    {
        $this->requireEd448Support();

        try {
            new Ed448PublicKey('Invalid Key!');
            $this->fail('An InvalidKeyException was expected.');
        } catch (InvalidKeyException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }

    /**
     * On runtimes without Ed448 support (PHP below 8.4), construction fails fast with a clear message.
     *
     * @throws Throwable
     */
    public function test_without_ed448_support_it_should_fail()
    {
        if (defined('OPENSSL_KEYTYPE_ED448')) {
            $this->markTestSkipped('This environment supports Ed448 keys.');
        }

        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Ed448 keys require PHP 8.4 or later with OpenSSL Ed448 support.');
        new Ed448PublicKey(__DIR__ . '/../../../assets/keys/ed448-public.pem');
    }
}
