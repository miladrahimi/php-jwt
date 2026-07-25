<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class PS512Test extends TestCase
{
    /**
     * A PSS signature over `Text` made by the OpenSSL CLI with the same key pair, hash, and salt length:
     * `openssl dgst -sha512 -sign rsa-private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1`.
     */
    private const OPENSSL_SIGNATURE =
        'ITdy4WWWcDpAYCzj/KTO5zJVYlE8y1XP8cZWHH7FcDJhzrscYD4Cj4vPASVcYj6q8kw4H18rce4nwZuyvRg5b7QayHAvSjLY'
        . 'iDqEjzTn/8scCRbCEKpGYRQjfwM7WWv5Io+80zqCx6Y/Y6JNTo7M6IwPki8DJWYGeR6tq8p2+FbPz3TtoCgRT/6sf9YoOdq+'
        . 'soLxdJkiifrXqyawevblrSLC8Ke4/Omdx20w4bUiuyRiOYh3L6/t+xsh656zf3W++ps82WhzWeyVeWupWP3k3yvku9nVVMVp'
        . 'VMyhwxgH+beahtuKv9gq75vx2HVSZ6eZabGR/MPJB/YMotu59ihyYA==';

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

        $signer = new PS512Signer($this->rsaPrivateKey);
        $signature = $signer->sign($plain);

        $verifier = new PS512Verifier($this->rsaPublicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new PS512Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new PS512Verifier($this->rsaPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * The verifier accepts a signature produced by an independent implementation (the OpenSSL CLI), pinning the
     * whole EMSA-PSS check (hash, MGF1, salt recovery, structure) to RFC 8017 rather than to this package.
     *
     * @throws Throwable
     */
    public function test_verify_with_an_openssl_cli_signature_it_should_pass()
    {
        $verifier = new PS512Verifier($this->rsaPublicKey);
        $verifier->verify('Text', (string)base64_decode(self::OPENSSL_SIGNATURE));

        $this->assertTrue(true);
    }

    /**
     * EMSA-PSS needs emLen >= hLen + sLen + 2 (RFC 8017 §9.1.1); a 1024-bit key gives emLen = 128, below the
     * 130 bytes PS512 needs, so signing must be refused instead of producing a malformed encoding.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_too_small_key_it_should_fail()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $pem);

        $signer = new PS512Signer(new RsaPrivateKey($pem));

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('The RSA key is too small for the `PS512` algorithm.');
        $signer->sign('Text');
    }

    /**
     * A 1040-bit key gives emLen = 130, exactly the RFC 8017 §9.1.1 minimum for PS512, so it must still work;
     * one bit fewer (emLen = 129 at 1032 bits) is covered by the too-small rejection above.
     *
     * @throws Throwable
     */
    public function test_sign_and_verify_with_the_minimum_key_size_it_should_pass()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1040, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $pem);
        $publicPem = openssl_pkey_get_details($resource)['key'];

        $signer = new PS512Signer(new RsaPrivateKey($pem));
        $signature = $signer->sign('Text');

        $verifier = new PS512Verifier(new RsaPublicKey($publicPem));
        $verifier->verify('Text', $signature);

        $this->assertTrue(true);
    }

    /**
     * One byte below the PS512 minimum (emLen = 129 at 1032 bits) must be refused.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_key_one_byte_below_the_minimum_it_should_fail()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1032, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($resource, $pem);

        $signer = new PS512Signer(new RsaPrivateKey($pem));

        $this->expectException(SigningException::class);
        $this->expectExceptionMessage('The RSA key is too small for the `PS512` algorithm.');
        $signer->sign('Text');
    }

    /**
     * A verifier holding a too-small key cannot have a consistent encoded message, so any signature of the
     * right length must be rejected as invalid (RFC 8017 §9.1.2 step 1).
     *
     * @throws Throwable
     */
    public function test_verify_with_a_too_small_key_it_should_fail()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $publicPem = openssl_pkey_get_details($resource)['key'];

        $verifier = new PS512Verifier(new RsaPublicKey($publicPem));

        // 128 bytes long (matching the key) and numerically far below the modulus, so the RSA operation itself
        // succeeds and the rejection can only come from the EMSA-PSS consistency check.
        $signature = str_repeat("\x00", 127) . "\x01";

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature is not valid.');
        $verifier->verify('Text', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_name_it_should_be_the_jwa_name()
    {
        $this->assertSame('PS512', (new PS512Signer($this->rsaPrivateKey))->name());
        $this->assertSame('PS512', (new PS512Verifier($this->rsaPublicKey))->name());
    }
}
