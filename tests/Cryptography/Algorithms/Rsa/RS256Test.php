<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
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
    public function test_verify_with_a_different_key_it_should_fail()
    {
        $signer = new RS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Text');

        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $otherPublicKey = new RsaPublicKey(openssl_pkey_get_details($resource)['key']);

        $verifier = new RS256Verifier($otherPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Text', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_with_an_unsupported_algorithm_it_should_fail()
    {
        $signer = new class ($this->rsaPrivateKey) extends RS256Signer {
            protected function algorithm(): int
            {
                return PHP_INT_MAX;
            }
        };

        // The digest check fails inside PHP before OpenSSL is reached, so the error queue stays empty and the
        // fallback message is used. Drain stale entries so the queue state is deterministic.
        while (openssl_error_string() !== false) {
            continue;
        }

        // Swallow the PHP warning OpenSSL raises alongside returning false.
        set_error_handler(function (): bool {
            return true;
        }, E_WARNING);

        try {
            $this->expectException(SigningException::class);
            $this->expectExceptionMessage('OpenSSL cannot sign the token.');
            $signer->sign('Text');
        } finally {
            restore_error_handler();
        }
    }

    /**
     * The exception carries the OpenSSL error explaining the failed verification. OpenSSL 3 reports the failure
     * through its error queue; OpenSSL 1.1 does not reliably queue one here, so the test needs OpenSSL 3+.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_wrong_signature_it_should_carry_the_openssl_error()
    {
        if (OPENSSL_VERSION_NUMBER < 0x30000000) {
            $this->markTestSkipped('This test requires OpenSSL 3.');
        }

        // Drain stale entries so the error queue state is deterministic.
        while (openssl_error_string() !== false) {
            continue;
        }

        $verifier = new RS256Verifier($this->rsaPublicKey);

        try {
            $verifier->verify('Plain', str_repeat("\x01", 256));
            $this->fail('An InvalidSignatureException was expected.');
        } catch (InvalidSignatureException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
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
