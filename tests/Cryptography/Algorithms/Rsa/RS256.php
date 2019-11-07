<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

class RS256 extends TestCase
{
    public function test_sign_and_verify_it_should_sign_with_given_key()
    {
        $plain = 'Header Payload';

        $signer = new RS256Signer($this->privateKey());
        $signature = $signer->sign($plain);

        $verifier = new RS256Verifier($this->publicKey());
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    public function test_sign_and_verify_it_should_fail_with_wrong_plain()
    {
        $signer = new RS256Signer($this->privateKey());
        $signature = $signer->sign('Header Payload');

        $verifier = new RS256Verifier($this->publicKey());

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('WRONG!', $signature);
    }
}
