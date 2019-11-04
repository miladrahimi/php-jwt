<?php

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\DefaultValidator;

class JwtParserTest extends TestCase
{
    public function test_with_invalid_jwt_it_should_throw_an_exception()
    {
        $key = '17e62166fc8586dfa4d1bc0e1742c08b';
        $jwt = 'eyJzdWIiOjEsImp0aSI6Mn0.MZz2BcbCDOFrq90GJ16E2lgkm9XFOfX_90Qt9hu_OEE';

        $this->expectException(InvalidTokenException::class);

        $parser = new JwtParser(new HS256($key));
        $parser->verifySignature($jwt);

        $parser->parse($jwt);
    }

    public function test_getter_and_setter_for_json_parser()
    {
        $jsonParser = new JsonParser();

        $parser = new JwtParser(new HS256('17e62166fc8586dfa4d1bc0e1742c08b'));
        $parser->setJsonParser($jsonParser);

        $this->assertSame($jsonParser, $parser->getJsonParser());
    }

    public function test_getter_and_setter_for_base64_parser()
    {
        $base64Parser = new Base64Parser();

        $parser = new JwtParser(new HS256('17e62166fc8586dfa4d1bc0e1742c08b'));
        $parser->setBase64Parser($base64Parser);

        $this->assertSame($base64Parser, $parser->getBase64Parser());
    }

    public function test_getter_for_verifier()
    {
        $verifier = new HS256('17e62166fc8586dfa4d1bc0e1742c08b');

        $parser = new JwtParser($verifier);

        $this->assertSame($verifier, $parser->getVerifier());
    }

    public function test_getter_and_setter_for_validator()
    {
        $validator = new DefaultValidator();

        $parser = new JwtParser(new HS256('17e62166fc8586dfa4d1bc0e1742c08b'));
        $parser->setValidator($validator);

        $this->assertSame($validator, $parser->getValidator());
    }
}
