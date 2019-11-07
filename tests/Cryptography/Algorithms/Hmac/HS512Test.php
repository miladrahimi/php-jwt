<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;

class HS512Test extends TestCase
{
    private function key(): string
    {
        return '12345678901234567890123456789012';
    }

    public function test_sign_and_verify_it_should_sign_with_given_key()
    {
        $plain = 'Header Payload';

        $signer = new HS512($this->key());
        $signature = $signer->sign($plain);
        $signer->verify($plain, $signature);

        $this->assertTrue(true);
    }

    public function test_sign_and_verify_it_should_fail_with_wrong_plain()
    {
        $signer = new HS512($this->key());
        $signature = $signer->sign('Header Payload');

        $this->expectException(InvalidSignatureException::class);
        $signer->verify('WRONG!', $signature);
    }
}
