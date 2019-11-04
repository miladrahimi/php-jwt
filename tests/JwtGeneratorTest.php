<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\JwtGenerator;

class JwtGeneratorTest extends TestCase
{
    public function test_json_parser_getter_and_setter()
    {
        $jsonParser = new JsonParser();

        $jwtGenerator = new JwtGenerator(new HS256('12345678901234567890123456789012'));
        $jwtGenerator->setJsonParser($jsonParser);

        $this->assertSame($jsonParser, $jwtGenerator->getJsonParser());
    }

    public function test_base64_parser_getter_and_setter()
    {
        $base64Parser = new Base64Parser();

        $jwtGenerator = new JwtGenerator(new HS256('12345678901234567890123456789012'));
        $jwtGenerator->setBase64Parser($base64Parser);

        $this->assertSame($base64Parser, $jwtGenerator->getBase64Parser());
    }

    public function test_signer_getter()
    {
        $signer = new HS256('12345678901234567890123456789012');

        $jwtGenerator = new JwtGenerator($signer);

        $this->assertSame($signer, $jwtGenerator->getSigner());
    }
}
