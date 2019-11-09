<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Generator;
use Throwable;

class GeneratorTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_generate_with_sample_claims_it_should_generate_jwt()
    {
        $generator = new Generator($this->signer);
        $jwt = $generator->generate($this->sampleClaims);

        $this->assertEquals($this->sampleJwt, $jwt);
    }

    public function test_set_and_get_signer()
    {
        $generator = new Generator($this->signer);

        $this->assertSame($this->signer, $generator->getSigner());
    }

    public function test_set_and_get_json_parser()
    {
        $jsonParser = new StrictJsonParser();
        $generator = new Generator($this->signer);
        $generator->setJsonParser($jsonParser);

        $this->assertSame($jsonParser, $generator->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $base64Parser = new SafeBase64Parser();
        $generator = new Generator($this->signer);
        $generator->setBase64Parser($base64Parser);

        $this->assertSame($base64Parser, $generator->getBase64Parser());
    }
}
