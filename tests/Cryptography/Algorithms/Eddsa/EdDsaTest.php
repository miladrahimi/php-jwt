<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class EdDsaTest extends TestCase
{
    protected string $privateKey;
    protected string $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = base64_decode(file_get_contents(__DIR__ . '/../../../../assets/keys/ed25519.sec'));
        $this->publicKey = base64_decode(file_get_contents(__DIR__ . '/../../../../assets/keys/ed25519.pub'));
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new EdDsaSigner($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new EdDsaVerifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new EdDsaSigner($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new EdDsaVerifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_it_should_fail_with_invalid_key()
    {
        $this->expectException(SigningException::class);

        $signer = new EdDsaSigner('Invalid Key!');
        $signer->sign('Header Payload');
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->privateKey;

        $signer = new EdDsaSigner($this->privateKey);

        $this->assertSame($key, $signer->getPrivateKey());
        $this->assertSame('EdDSA', $signer->name());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->publicKey;

        $verifier = new EdDsaVerifier($this->publicKey);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
