<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS512Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;

class RS512 extends TestCase
{
    public function test_sign_and_verify_it_should_sign_with_given_key()
    {
        $plain = 'Header Payload';

        $signer = new RS512Signer($this->privateKey());
        $signature = $signer->sign($plain);

        $verifier = new RS512Verifier($this->publicKey());
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    public function test_sign_and_verify_it_should_fail_with_wrong_plain()
    {
        $signer = new RS512Signer($this->privateKey());
        $signature = $signer->sign('Header Payload');

        $verifier = new RS512Verifier($this->publicKey());

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('WRONG!', $signature);
    }
}
