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
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use MiladRahimi\Jwt\Validator\Rules\GreaterThan;
use Throwable;

class ExamplesTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_simple_example()
    {
        $signer = new HS256('12345678901234567890123456789012');

        // Generate a token
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

        // Parse the token
        $parser = new Parser($signer);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_rsa_algorithms()
    {
        $privateKey = new RsaPrivateKey(__DIR__ . '/../assets/keys/rsa-private.pem');
        $publicKey = new RsaPublicKey(__DIR__ . '/../assets/keys/rsa-public.pem');

        $signer = new RS256Signer($privateKey);
        $verifier = new RS256Verifier($publicKey);

        // Generate a token
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

        // Parse the token
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_ecdsa_algorithms()
    {
        $privateKey = new EcdsaPrivateKey(__DIR__ . '/../assets/keys/ecdsa384-private.pem');
        $publicKey = new EcdsaPublicKey(__DIR__ . '/../assets/keys/ecdsa384-public.pem');

        $signer = new ES384Signer($privateKey);
        $verifier = new ES384Verifier($publicKey);

        // Generate a token
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

        // Parse the token
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_eddsa_algorithms()
    {
        $privateKey = base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.sec'));
        $publicKey = base64_decode(file_get_contents(__DIR__ . '/../assets/keys/ed25519.pub'));

        $signer = new EdDsaSigner($privateKey);
        $verifier = new EdDsaVerifier($publicKey);

        // Generate a token
        $generator = new Generator($signer);
        $jwt = $generator->generate(['id' => 666, 'is-admin' => true]);

        // Parse the token
        $parser = new Parser($verifier);
        $claims = $parser->parse($jwt);

        $this->assertEquals(['id' => 666, 'is-admin' => true], $claims);
    }

    /**
     * @throws Throwable
     */
    public function test_validation()
    {
        $jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NjY2LCJpcy1hZG1pbiI6dHJ1ZX0.Abq2XaKQKCxGEdp9_CHsT8FHL1VGAoE76q7zx8-uqX0';

        $signer = new HS256('12345678901234567890123456789012');

        // Add Validation
        $validator = new DefaultValidator();
        $validator->addRule('is-admin', new EqualsTo(true));
        $validator->addRule('id', new GreaterThan(600));

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
