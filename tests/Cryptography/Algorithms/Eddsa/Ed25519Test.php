<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\Ed25519Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class Ed25519Test extends TestCase
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

        $signer = new Ed25519Signer($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new Ed25519Verifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new Ed25519Signer($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new Ed25519Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * Ed25519 is the RFC 9864 fully-specified name for EdDSA; both signers must produce identical signatures.
     *
     * @throws Throwable
     */
    public function test_sign_it_should_produce_the_same_signature_as_eddsa()
    {
        $ed25519Signature = (new Ed25519Signer($this->privateKey))->sign('Text');
        $edDsaSignature = (new EdDsaSigner($this->privateKey))->sign('Text');

        $this->assertSame($edDsaSignature, $ed25519Signature);
    }

    /**
     * @throws Throwable
     */
    public function test_generate_and_parse_the_token_header_should_declare_ed25519()
    {
        $generator = new Generator(new Ed25519Signer($this->privateKey));
        $jwt = $generator->generate(['id' => 666]);

        $header = json_decode(base64_decode(explode('.', $jwt)[0]), true);
        $this->assertSame('Ed25519', $header['alg']);

        $parser = new Parser(new Ed25519Verifier($this->publicKey));
        $this->assertEquals(['id' => 666], $parser->parse($jwt));
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $signer = new Ed25519Signer($this->privateKey);

        $this->assertSame($this->privateKey, $signer->getPrivateKey());
        $this->assertSame('Ed25519', $signer->name());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $verifier = new Ed25519Verifier($this->publicKey);
        $this->assertSame($this->publicKey, $verifier->getPublicKey());
    }

    /**
     * @throws Throwable
     */
    public function test_name()
    {
        $verifier = new Ed25519Verifier($this->publicKey);
        $this->assertSame('Ed25519', $verifier->name());
    }

    /**
     * @throws Throwable
     */
    public function test_kid()
    {
        $verifier = new Ed25519Verifier($this->publicKey);
        $this->assertSame($this->publicKey->getId(), $verifier->kid());
    }
}
