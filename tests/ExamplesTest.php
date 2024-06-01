<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaSigner;
use MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa\EdDsaVerifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use MiladRahimi\Jwt\Validator\Rules\GreaterThan;
use MiladRahimi\Jwt\VerifierFactory;
use Throwable;

class ExamplesTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_simple_example()
    {
        $key = new HmacKey('12345678901234567890123456789012');
        $signer = new HS256($key);

        // Generate a token
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

        // Parse the token
        $parser = new Parser($signer);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 13, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_rsa_algorithms()
    {
        // Generate a token
        $privateKey = new RsaPrivateKey(__DIR__ . '/../assets/keys/rsa-private.pem');
        $signer = new RS256Signer($privateKey);
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

        // Parse the token
        $publicKey = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem');
        $verifier = new RS256Verifier($publicKey);
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 13, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_ecdsa_algorithms()
    {
        // Generate a token
        $privateKey = new EcdsaPrivateKey(__DIR__ . '/../assets/keys/ecdsa384-private.pem');
        $signer = new ES384Signer($privateKey);
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 13, 'is-admin' => true]);

        // Parse the token
        $publicKey = new EcdsaPublicKey(__DIR__ . '/../assets/keys/ecdsa384-public.pem');
        $verifier = new ES384Verifier($publicKey);
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 13, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_eddsa_algorithms()
    {
        // Generate a token
        $privateKey = new EdDsaPrivateKey(
            base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.sec'))
        );
        $signer = new EdDsaSigner($privateKey);
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

        // Parse the token
        $publicKey = new EdDsaPublicKey(
            base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.pub'))
        );
        $verifier = new EdDsaVerifier($publicKey);
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_multiple_keys()
    {
        $privateKey1 = new RsaPrivateKey(
            __DIR__ . '/../assets/keys/rsa-private.pem',
            '',
            'key-1'
        );
        $publicKey1 = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem', 'key-1');

        $privateKey2 = new EcdsaPrivateKey(
            __DIR__ . '/../assets/keys/ecdsa384-private.pem',
            '',
            'key-2'
        );
        $publicKey2 = new EcdsaPublicKey(__DIR__ . '/../assets/keys/ecdsa384-public.pem', 'key-2');

        // Generate tokens

        $signer1 = new RS256Signer($privateKey1);
        $generator1 = new Generator($signer1);
        $jwt1 = $generator1->generate(['id' => 13, 'is-admin' => true]);

        $signer2 = new ES384Signer($privateKey2);
        $generator2 = new Generator($signer2);
        $jwt2 = $generator2->generate(['id' => 13, 'is-admin' => true]);

        // Parse tokens

        $verifierFactory = new VerifierFactory([
            new RS256Verifier($publicKey1),
            new ES384Verifier($publicKey2),
        ]);

        $verifier1 = $verifierFactory->getVerifier($jwt1);
        $parser1 = new Parser($verifier1);
        $claims = $parser1->parse($jwt1);
        $this->assertEquals(['id' => 13, 'is-admin' => true], $claims);

        $verifier2 = $verifierFactory->getVerifier($jwt2);
        $parser2 = new Parser($verifier2);
        $claims = $parser2->parse($jwt2);
        $this->assertEquals(['id' => 13, 'is-admin' => true], $claims);

        $this->expectException(InvalidTokenException::class);
        $parser1->parse($jwt2);

        $this->expectException(InvalidTokenException::class);
        $parser2->parse($jwt1);
    }

    /**
     * @throws Throwable
     */
    public function test_validation()
    {
        $jwt = join('.', [
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9',
            'eyJpZCI6NjY2LCJpcy1hZG1pbiI6dHJ1ZX0',
            'Abq2XaKQKCxGEdp9_CHsT8FHL1VGAoE76q7zx8-uqX0',
        ]);

        $signer = new HS256(new HmacKey('12345678901234567890123456789012'));

        // Add Validation
        $validator = new DefaultValidator();
        $validator->addRequiredRule('is-admin', new EqualsTo(true));
        $validator->addRequiredRule('id', new GreaterThan(600));

        // Parse the token
        $parser = new Parser($signer, $validator);
        try {
            $claims = $parser->parse($jwt);
            $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
        } catch (ValidationException $e) {
            // Handle error.
            $this->fail();
        }
    }
}
