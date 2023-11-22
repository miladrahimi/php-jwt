<?php

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class EdDsaTest extends TestCase
{
    protected EdDsaPrivateKey $privateKey;
    protected EdDsaPublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new EdDsaPrivateKey(
            base64_decode(file_get_contents(__DIR__ . '/../../../../assets/keys/ed25519.sec')),
            'id-1'
        );
        $this->publicKey = new EdDsaPublicKey(
            base64_decode(file_get_contents(__DIR__ . '/../../../../assets/keys/ed25519.pub')),
            'id-1'
        );
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

        $signer = new EdDsaSigner(new EdDsaPrivateKey('Invalid Key!'));
        $signer->sign('Header Payload');
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $signer = new EdDsaSigner($this->privateKey);

        $this->assertSame($this->privateKey, $signer->getPrivateKey());
        $this->assertSame('EdDSA', $signer->name());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $verifier = new EdDsaVerifier($this->publicKey);
        $this->assertSame($this->publicKey, $verifier->getPublicKey());
    }

    /**
     * @throws Throwable
     */
    public function test_name()
    {
        $verifier = new EdDsaVerifier($this->publicKey);
        $this->assertSame('EdDSA', $verifier->name());
    }

    /**
     * @throws Throwable
     */
    public function test_kid()
    {
        $verifier = new EdDsaVerifier($this->publicKey);
        $this->assertSame($this->publicKey->getId(), $verifier->kid());
    }
}
