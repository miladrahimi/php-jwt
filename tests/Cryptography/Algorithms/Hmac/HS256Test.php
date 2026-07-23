<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class HS256Test extends TestCase
{
    protected HmacKey $key;

    public function setUp(): void
    {
        parent::setUp();

        $this->key = new HmacKey('12345678901234567890123456789012');
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_it_should_sign_and_verify_with_the_key()
    {
        $plain = 'Text';

        $signer = new HS256($this->key);
        $signature = $signer->sign($plain);
        $signer->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_it_should_fail_with_different_plains()
    {
        $signer = new HS256($this->key);
        $signature = $signer->sign('Text');

        $this->expectException(InvalidSignatureException::class);
        $signer->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_key_it_should_fail()
    {
        $this->expectException(SigningException::class);
        $signer = new HS256(new HmacKey('Invalid Key'));
        $signer->sign('Text');
    }

    /**
     * The documented key-length bounds `[32, 6144]` are inclusive.
     *
     * @throws Throwable
     */
    public function test_sign_with_boundary_key_lengths_it_should_pass()
    {
        $this->assertNotEmpty((new HS256(new HmacKey(str_repeat('k', 32))))->sign('Text'));
        $this->assertNotEmpty((new HS256(new HmacKey(str_repeat('k', 6144))))->sign('Text'));
    }

    /**
     * @throws Throwable
     */
    public function test_sign_with_a_key_over_the_maximum_length_it_should_fail()
    {
        $this->expectException(SigningException::class);
        (new HS256(new HmacKey(str_repeat('k', 6145))))->sign('Text');
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_different_key_it_should_fail()
    {
        $signature = (new HS256(new HmacKey(str_repeat('a', 32))))->sign('Text');

        $verifier = new HS256(new HmacKey(str_repeat('b', 32)));

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Text', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_key()
    {
        $signer = new HS256($this->key);

        $this->assertSame($this->key, $signer->getKey());
    }
}
