<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed448Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class Ed448Test extends TestCase
{
    protected Ed448PrivateKey $privateKey;

    protected Ed448PublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        if (!defined('OPENSSL_KEYTYPE_ED448')) {
            $this->markTestSkipped('The `Ed448` algorithm requires PHP 8.4 or later with OpenSSL Ed448 support.');
        }

        $this->privateKey = new Ed448PrivateKey(__DIR__ . '/../../../../assets/keys/ed448-private.pem', '', 'id-1');
        $this->publicKey = new Ed448PublicKey(__DIR__ . '/../../../../assets/keys/ed448-public.pem', 'id-1');
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new Ed448Signer($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new Ed448Verifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new Ed448Signer($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new Ed448Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_generate_and_parse_the_token_header_should_declare_ed448()
    {
        $generator = new Generator(new Ed448Signer($this->privateKey));
        $jwt = $generator->generate(['id' => 666]);

        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);
        $this->assertSame('Ed448', $header['alg']);

        $parser = new Parser(new Ed448Verifier($this->publicKey));
        $this->assertEquals(['id' => 666], $parser->parse($jwt));
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_different_key_it_should_fail()
    {
        $signature = (new Ed448Signer($this->privateKey))->sign('Text');

        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED448]);
        $otherPublicKey = new Ed448PublicKey(openssl_pkey_get_details($resource)['key']);

        $verifier = new Ed448Verifier($otherPublicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Text', $signature);
    }

    /**
     * An X448 key loads fine but cannot sign, so OpenSSL fails and the exception carries its error message.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_non_signing_key_it_should_carry_the_openssl_error()
    {
        while (openssl_error_string() !== false) {
            continue;
        }

        $signer = new Ed448Signer(new Ed448PrivateKey(__DIR__ . '/../../../../assets/keys/x448-private.pem'));

        try {
            $signer->sign('Text');
            $this->fail('A SigningException was expected.');
        } catch (SigningException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }

    /**
     * The exception surfaces the pending OpenSSL error instead of the generic fallback message. The queue is
     * drained and re-seeded with a known error to make its state deterministic across platforms.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_wrong_signature_it_should_carry_the_openssl_error()
    {
        while (openssl_error_string() !== false) {
            continue;
        }
        openssl_pkey_get_private('not-a-valid-key');

        $verifier = new Ed448Verifier($this->publicKey);

        try {
            $verifier->verify('Plain', str_repeat("\x01", 114));
            $this->fail('An InvalidSignatureException was expected.');
        } catch (InvalidSignatureException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_an_empty_signature_it_should_fail()
    {
        $verifier = new Ed448Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Header Payload', '');
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $signer = new Ed448Signer($this->privateKey);

        $this->assertSame($this->privateKey, $signer->getPrivateKey());
        $this->assertSame('Ed448', $signer->name());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $verifier = new Ed448Verifier($this->publicKey);
        $this->assertSame($this->publicKey, $verifier->getPublicKey());
    }

    /**
     * @throws Throwable
     */
    public function test_name()
    {
        $verifier = new Ed448Verifier($this->publicKey);
        $this->assertSame('Ed448', $verifier->name());
    }

    /**
     * @throws Throwable
     */
    public function test_kid()
    {
        $signer = new Ed448Signer($this->privateKey);
        $verifier = new Ed448Verifier($this->publicKey);

        $this->assertSame('id-1', $signer->kid());
        $this->assertSame('id-1', $verifier->kid());
    }
}
