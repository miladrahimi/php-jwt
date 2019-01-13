<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS384;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS512;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;

class HSTest extends TestCase
{
    private $key;

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
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
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
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
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidKeyException
     * @throws \MiladRahimi\Jwt\Exceptions\InvalidTokenException
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
}
