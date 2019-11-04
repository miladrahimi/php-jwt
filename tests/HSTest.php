<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS384;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

class HSTest extends TestCase
{
    private $key;

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_hs256_it_should_generate_jwt_and_parse_it()
    {
        $generator = new JwtGenerator(new HS256($this->key()));
        $jwt = $generator->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new HS256($this->key()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    private function key(): string
    {
        return $this->key ?: $this->key = md5(mt_rand(1, 100));
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_hs384_signer_it_should_generate_jwt_and_parse_it()
    {
        $service = new JwtGenerator(new HS384($this->key()));
        $jwt = $service->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new HS384($this->key()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_hs512_signer_it_should_generate_jwt_and_parse_it()
    {
        $service = new JwtGenerator(new HS512($this->key()));
        $jwt = $service->generate(['sub' => 1, 'jti' => 2]);

        $parser = new JwtParser(new HS512($this->key()));
        $parser->verifySignature($jwt);
        $parser->validate($jwt);
        $claims = $parser->parse($jwt);

        $this->assertEquals($claims['sub'], 1);
        $this->assertEquals($claims['jti'], 2);
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_hs512_signer_it_should_throw_e_when_signature_is_invalid()
    {
        $service = new JwtGenerator(new HS512($this->key()));
        $jwt = $service->generate(['sub' => 1, 'jti' => 2]);
        $newJwt = substr($jwt, strpos($jwt, '.'));

        $parser = new JwtParser(new HS512($this->key()));

        $this->expectException(InvalidSignatureException::class);
        $parser->verifySignature($newJwt);
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_custom_base64_parser()
    {
        $base64Parser = new Base64Parser();

        $signer = new HS512($this->key(), $base64Parser);

        $this->assertSame($base64Parser, $signer->getBase64Parser());
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_with_wrong_key_it_should_raise_an_exception()
    {
        $this->expectException(InvalidKeyException::class);
        new HS512('Wrong Key');
    }

    /**
     * @throws InvalidKeyException
     * @throws InvalidTokenException
     */
    public function test_setter_and_getter_for_key()
    {
        $key = $this->key();

        $signer = new HS512($key);

        $this->assertEquals($key, $signer->getKey());
    }
}
