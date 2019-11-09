<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS384Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class RS384Test extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_it_should_sign_with_given_key()
    {
        $plain = 'Header Payload';

        $signer = new RS384Signer($this->privateKey());
        $signature = $signer->sign($plain);

        $verifier = new RS384Verifier($this->publicKey());
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_it_should_fail_with_wrong_plain()
    {
        $signer = new RS384Signer($this->privateKey());
        $signature = $signer->sign('Header Payload');

        $verifier = new RS384Verifier($this->publicKey());

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('WRONG!', $signature);
    }
}
