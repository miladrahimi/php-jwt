<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES512Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Parser;
use Throwable;

/**
 * Known-answer tests against tokens and signatures produced outside this library (RFC test vectors).
 *
 * Round-trip tests cannot catch a bug that is symmetric in sign() and verify() (such as hashing with the wrong
 * digest on both sides); these vectors pin interoperability with compliant implementations.
 */
class InteropTest extends TestCase
{
    /**
     * Verifies the HS256 example token from RFC 7515 Appendix A.1.
     *
     * @throws Throwable
     */
    public function test_verify_the_rfc7515_hs256_example_token()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
            . '.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
            . '.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        $key = (new SafeBase64Parser())->decode(
            'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow'
        );

        $parser = new Parser(new HS256(new HmacKey($key)));
        $parser->verify($jwt);

        $this->assertTrue(true);
    }

    /**
     * Verifies the ES512 example signature from RFC 7515 Appendix A.4.
     *
     * The PEM below is the appendix's P-521 JWK public key (x, y) re-encoded as a SubjectPublicKeyInfo; both
     * coordinates and the signature halves are 66 bytes — the ceil(521 / 8) size this vector pins down.
     *
     * @throws Throwable
     */
    public function test_verify_the_rfc7515_es512_example_signature()
    {
        $publicKey = new EcdsaPublicKey(
            "-----BEGIN PUBLIC KEY-----\n"
            . "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB6SkFDxJPxrxVx9U5M2Xfne9KsMIs\n"
            . "sleY+TTrBOPGuuNwGlenkQ6dgb82MVno68sVXWNJ9L22zPipTFxZx6rBAaQANKZE\n"
            . "DjdnUNI3H9G9wsjztx0vTuXqNDLIFcyjFWD+XZOH7HdLVYOGMOXLv1qMvgqR3QBk\n"
            . "xpmaH25uZ/rd7eTIyPY=\n"
            . "-----END PUBLIC KEY-----\n"
        );

        $signingInput = 'eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA';
        $signature = (new SafeBase64Parser())->decode(
            'AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZq'
            . 'wqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8Kp'
            . 'EHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn'
        );

        $verifier = new ES512Verifier($publicKey);
        $verifier->verify($signingInput, $signature);

        $this->assertTrue(true);
    }

    /**
     * Verifies the Ed25519 example signature from RFC 8037 Appendix A.4/A.5.
     *
     * @throws Throwable
     */
    public function test_verify_the_rfc8037_ed25519_example_signature()
    {
        $publicKey = new EdDsaPublicKey(
            hex2bin('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        );

        $signingInput = 'eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = (new SafeBase64Parser())->decode(
            'hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg'
        );

        $verifier = new EdDsaVerifier($publicKey);
        $verifier->verify($signingInput, $signature);

        $this->assertTrue(true);
    }

    /**
     * Verifies an `Ed25519` (RFC 9864) signature produced by the OpenSSL CLI, so libsodium checks the output
     * of an independent implementation. The key is the RFC 8037 Appendix A.1 pair and the payload matches the
     * RFC 8037 Appendix A.4 example; only the header differs (`{"alg":"Ed25519"}`). Regenerate with:
     * `openssl pkeyutl -sign -rawin -inkey <rfc8037-key.pem> -in <signing-input>`.
     *
     * @throws Throwable
     */
    public function test_verify_the_openssl_ed25519_example_signature()
    {
        $publicKey = new EdDsaPublicKey(
            hex2bin('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        );

        $signingInput = 'eyJhbGciOiJFZDI1NTE5In0.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc';
        $signature = (new SafeBase64Parser())->decode(
            'UxhIYLHGg39NVCLpQAVD_UcfOmnGSCzLFZoXYkLiIbFccmOb_qObsgjzLKsfJw-4NlccUgvYrEHrRbNV0HcZAQ'
        );

        $verifier = new Ed25519Verifier($publicKey);
        $verifier->verify($signingInput, $signature);

        $this->assertTrue(true);
    }

    /**
     * Verifies an `Ed448` (RFC 9864) signature produced by the OpenSSL CLI with the test key pair, pinning the
     * signature format (raw 114 bytes) and the header (`{"alg":"Ed448"}`) against drift. Regenerate with:
     * `openssl pkeyutl -sign -rawin -inkey assets/keys/ed448-private.pem -in <signing-input>`.
     *
     * @throws Throwable
     */
    public function test_verify_the_openssl_ed448_example_signature()
    {
        if (!defined('OPENSSL_KEYTYPE_ED448')) {
            $this->markTestSkipped('The `Ed448` algorithm requires PHP 8.4 or later with OpenSSL Ed448 support.');
        }

        $publicKey = new Ed448PublicKey(__DIR__ . '/../assets/keys/ed448-public.pem');

        $signingInput = 'eyJhbGciOiJFZDQ0OCJ9.RXhhbXBsZSBvZiBFZDQ0OCBzaWduaW5n';
        $signature = (new SafeBase64Parser())->decode(
            'wtleX23Jt23w5vgNjQC3jihdYbhnUXHHP8VMRJuxWMS9SqJxXIXE1AlGh8JX7LUfQwksHEmhIQWAAAd9TLIrob05r4'
            . 'VKc0hgkGMA88ljBjvYy4W_dYI4xrQRSZfQ0TBcZMQ9o4X0JKE7sE-wGvM_Sz8A'
        );

        $verifier = new Ed448Verifier($publicKey);
        $verifier->verify($signingInput, $signature);

        $this->assertTrue(true);
    }
}
