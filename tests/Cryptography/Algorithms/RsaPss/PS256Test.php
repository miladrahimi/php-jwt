<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class PS256Test extends TestCase
{
    /**
     * A PSS signature over `Text` made by the OpenSSL CLI with the same key pair, hash, and salt length:
     * `openssl dgst -sha256 -sign rsa-private.pem -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1`.
     */
    private const OPENSSL_SIGNATURE =
        'KTwM/3VPa1o9s3nZDM9AuTQYFA1m4t+D06eKYtYCw1Ia47yJDbeFBPp6TP4HI8lggE1czM8fkrJvlyGidUukmT75LUYqWb0X'
        . 'QF+lIpOgmhhVvbUHQ57gv6q/JE4djRvdq8AorirTPdX1VhbBW0hT79VU2G5GL26xgRGRdb6FeaISZnWYSNfjn7vNlLDvkq+R'
        . '6zJCl4OMU5ug3aqHYJd0M9VaWDrzaOgOPj7ZTZZIkAPW9VBxnzNJ34gL2ga+TRtPZqj7RoI6GAjCYT60cb4T16nhW3OYz41/'
        . 'o4Qkc4bakzbdonS7LSt7FBuaAzBqmSQ1nMozxpDHKTiPlvtNPRSa5A==';

    /**
     * The same OpenSSL CLI signature over `Text` but with `rsa_pss_saltlen:20`; RFC 7518 §3.5 requires the salt
     * length to equal the hash output length, so the strict verifier must reject it.
     */
    private const OPENSSL_SIGNATURE_SHORT_SALT =
        'KguWhNatFih0dy8yDLysblg+Ki+2Eev0p2abGeApIp2qwB14PWKTPG/ZxZyO9ZVpSp/YjjVU1R4wmbwNu9xaOg9L8Qyzv3Tg'
        . 'X2N5l6cxPIrFWz4Qtv+nsZuFF8dK/dTvahJ4cYDYy+WnqxoOF9+M8UQnQbtOUAM2NCmZnSPxwH0sQxnPamcS/oCIttZMuArT'
        . 'it5KK2GqGoc3EtDCACviQg+2nTfw1ogCALhf3geYK3R9BUPrVc2swpnTlP4/6uVDsnFw/tt43D5u4qbxqp3H/zLK8LF7Obf5'
        . 'zPOFVbzm0a/V2aTqFyWmt++o0SDakjX885rBbUTahc1R5cBmvRgLjA==';

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

        $signer = new PS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign($plain);

        $verifier = new PS256Verifier($this->rsaPublicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new PS256Verifier($this->rsaPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_different_key_it_should_fail()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);
        $signature = $signer->sign('Text');

        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $otherPublicKey = new RsaPublicKey(openssl_pkey_get_details($resource)['key']);

        $verifier = new PS256Verifier($otherPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Text', $signature);
    }

    /**
     * The verifier accepts a signature produced by an independent implementation (the OpenSSL CLI), pinning the
     * whole EMSA-PSS check (hash, MGF1, salt recovery, structure) to RFC 8017 rather than to this package.
     *
     * @throws Throwable
     */
    public function test_verify_with_an_openssl_cli_signature_it_should_pass()
    {
        $verifier = new PS256Verifier($this->rsaPublicKey);
        $verifier->verify('Text', (string)base64_decode(self::OPENSSL_SIGNATURE));

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_short_salt_signature_it_should_fail()
    {
        $verifier = new PS256Verifier($this->rsaPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature is not valid.');
        $verifier->verify('Text', (string)base64_decode(self::OPENSSL_SIGNATURE_SHORT_SALT));
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_wrong_length_signature_it_should_fail()
    {
        $verifier = new PS256Verifier($this->rsaPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', 'too-short');
    }

    /**
     * @throws Throwable
     */
    public function test_name_it_should_be_the_jwa_name()
    {
        $this->assertSame('PS256', (new PS256Signer($this->rsaPrivateKey))->name());
        $this->assertSame('PS256', (new PS256Verifier($this->rsaPublicKey))->name());
    }

    /**
     * @throws Throwable
     */
    public function test_kid_it_should_return_the_key_id()
    {
        $privateKey = new RsaPrivateKey(__DIR__ . '/../../../../assets/keys/rsa-private.pem', '', 'key-1');
        $publicKey = new RsaPublicKey(__DIR__ . '/../../../../assets/keys/rsa-public.pem', 'key-1');

        $this->assertSame('key-1', (new PS256Signer($privateKey))->kid());
        $this->assertSame('key-1', (new PS256Verifier($publicKey))->kid());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->rsaPrivateKey;

        $signer = new PS256Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->rsaPublicKey;

        $verifier = new PS256Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
