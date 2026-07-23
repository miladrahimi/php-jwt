<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class ES256Test extends TestCase
{
    protected EcdsaPrivateKey $privateKey;
    protected EcdsaPublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new EcdsaPrivateKey(__DIR__ . '/../../../../assets/keys/ecdsa256-private.pem');
        $this->publicKey = new EcdsaPublicKey(__DIR__ . '/../../../../assets/keys/ecdsa256-public.pem');
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new ES256Signer($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new ES256Verifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new ES256Signer($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new ES256Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * A raw signature whose length does not match the curve must be rejected before any DER conversion is attempted.
     *
     * @throws Throwable
     */
    public function test_verify_with_empty_signature_it_should_fail()
    {
        $verifier = new ES256Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', '');
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_truncated_signature_it_should_fail()
    {
        $signer = new ES256Signer($this->privateKey);
        $signature = $signer->sign('Text');

        $verifier = new ES256Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', substr($signature, 0, -1));
    }

    /**
     * A well-sized but all-zero signature must be rejected by verification, not crash the raw-to-DER conversion.
     *
     * @throws Throwable
     */
    public function test_verify_with_all_zero_signature_it_should_fail()
    {
        $verifier = new ES256Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Text', str_repeat("\x00", 64));
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->privateKey;

        $signer = new ES256Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->publicKey;

        $verifier = new ES256Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
