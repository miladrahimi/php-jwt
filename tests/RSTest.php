<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Signer as RS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS384Signer as RS384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS512Signer as RS512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS256Verifier as RS256Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS384Verifier as RS384Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\RS512Verifier as RS512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

class RSTest extends TestCase
{
    /**
     * @var PublicKey
     */
    private $publicKey;

    /**
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * @return PrivateKey
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     */
    private function privateKey(): PrivateKey
    {
        return $this->privateKey ?: $this->privateKey = new PrivateKey(__DIR__ . '/keys/private.pem');
    }

    /**
     * @return PublicKey
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     */
    private function publicKey(): PublicKey
    {
        return $this->publicKey ?: $this->publicKey = new PublicKey(__DIR__ . '/keys/public.pem');
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     */
    public function test_with_hs256_signer_it_should_generate_jwt_and_parse_it()
    {
        $generator = new JwtGenerator(new RS256Signer($this->privateKey()));
        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new RS256Verifier($this->publicKey()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
     */
    public function test_with_hs384_signer_it_should_generate_jwt_and_parse_it()
    {
        $generator = new JwtGenerator(new RS384Signer($this->privateKey()));
        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new RS384Verifier($this->publicKey()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
     */
    public function test_with_hs512_signer_it_should_generate_jwt_and_parse_it()
    {
        $generator = new JwtGenerator(new RS512Signer($this->privateKey()));
        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new RS512Verifier($this->publicKey()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    public function test_get_and_set_public_key()
    {
        $key = $this->publicKey();

        $verifier = new RS512Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }

    public function test_get_and_set_private_key()
    {
        $key = $this->privateKey();

        $signer = new RS256Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }
}
