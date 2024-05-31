<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class RS256Test extends TestCase
{
    protected RsaPrivateKey $rsaPrivateKey;

    protected RsaPublicKey $rsaPublicKey;

    /**
     * @throws Throwable
     * @throws InvalidKeyException
     */
    public function setUp(): void
    {
        parent::setUp();

        $this->rsaPrivateKey = new RsaPrivateKey(__DIR__ . '/../../../../assets/keys/rsa-private.pem');
        $this->rsaPublicKey = new RsaPublicKey(__DIR__ . '/../../../../assets/keys/rsa-public.pem');
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new RS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign($plain);

        $verifier = new RS256Verifier($this->rsaPublicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new RS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new RS256Verifier($this->rsaPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->rsaPrivateKey;

        $signer = new RS256Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->rsaPublicKey;

        $verifier = new RS256Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
