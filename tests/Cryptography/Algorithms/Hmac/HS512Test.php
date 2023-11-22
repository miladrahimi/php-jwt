<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class HS512Test extends TestCase
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

        $signer = new HS512($this->key);
        $signature = $signer->sign($plain);
        $signer->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_it_should_fail_with_different_plains()
    {
        $signer = new HS512($this->key);
        $signature = $signer->sign('Text');

        $this->expectException(InvalidSignatureException::class);
        $signer->verify('Different!', $signature);
    }
}
