<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\JwtGenerator;

class JwtGeneratorTest extends TestCase
{
    public function test_set_and_get_json_parser()
    {
        $generator = new JwtGenerator($this->signer);
        $jsonParser = new StrictJsonParser();
        $generator->setJsonParser($jsonParser);

        $this->assertSame($jsonParser, $generator->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $generator = new JwtGenerator($this->signer);
        $base64Parser = new SafeBase64Parser();
        $generator->setBase64Parser($base64Parser);

        $this->assertSame($base64Parser, $generator->getBase64Parser());
    }
}
