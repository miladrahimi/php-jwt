<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS384Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class PS384Test extends TestCase
{
    /**
     * A PSS signature over `Text` made by the OpenSSL CLI with the same key pair, hash, and salt length:
     * `openssl dgst -sha384 -sign rsa-private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1`.
     */
    private const OPENSSL_SIGNATURE =
        'Br4fuVLYjGgRhk1QhDJOpTFS3BzSmJmD6GKOEed+MfSJgeAYJfeDk9SxgDBHo1rSsCSNTwDVkp1MvrsbaBXg/NdxdO4yilxe'
        . 'C2yk+fQUh63+WgHwW0cQg98QXkpWlgi2YccxfBgcD5KNEvRT3849D1Whe7ECO3yKIGuLjoVDj6VPWC11j7IAlooU3mMM9h+x'
        . 'UG3efULdQ7WL9oJ/QWuZlPHLG4of/t9P+YzUa4czdF0AZFNy42sD7tIPrCR+qmpvuXBahatTILao9Aqo2hyPfFRtd4VZ1QCG'
        . 'q3ugsrHVCKB8SY+StfsQAWE+XfJcWFoAqaNHyRk67zPPCbW07viOdg==';

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

        $signer = new PS384Signer($this->rsaPrivateKey);
        $signature = $signer->sign($plain);

        $verifier = new PS384Verifier($this->rsaPublicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new PS384Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new PS384Verifier($this->rsaPublicKey);

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
        $verifier = new PS384Verifier($this->rsaPublicKey);
        $verifier->verify('Text', (string)base64_decode(self::OPENSSL_SIGNATURE));

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_name_it_should_be_the_jwa_name()
    {
        $this->assertSame('PS384', (new PS384Signer($this->rsaPrivateKey))->name());
        $this->assertSame('PS384', (new PS384Verifier($this->rsaPublicKey))->name());
    }
}
