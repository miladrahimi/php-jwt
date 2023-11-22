<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Generator;
use Throwable;

class GeneratorTest extends TestCase
{
    protected Signer $signer;

    public function setUp(): void
    {
        parent::setUp();

        $this->signer = new HS256(new HmacKey('12345678901234567890123456789012'));
    }

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
        $generator = new Generator($this->signer, $jsonParser);

        $this->assertSame($jsonParser, $generator->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $base64Parser = new SafeBase64Parser();
        $generator = new Generator($this->signer, null, $base64Parser);

        $this->assertSame($base64Parser, $generator->getBase64Parser());
    }
}
