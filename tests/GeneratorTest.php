<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Parser;
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

    /**
     * Claims survive the JSON/base64url round trip unchanged, including multibyte text and characters whose
     * base64 encoding exercises the URL-safe `-`/`_` alphabet.
     *
     * @throws Throwable
     */
    public function test_generate_with_unicode_claims_it_should_round_trip()
    {
        $claims = [
            'name' => 'Pink Floyd',
            'localized' => 'پینک فلوید',
            'emoji' => '🔐✓',
            'chars' => '~~~???>>>',
        ];

        $generator = new Generator($this->signer);
        $jwt = $generator->generate($claims);

        $parser = new Parser($this->signer);
        $this->assertSame($claims, $parser->parse($jwt));
    }

    /**
     * A generator configured with a custom type emits it as the header `typ` field, producing OAuth 2.0 access
     * tokens (RFC 9068) that a parser configured for the same type accepts.
     *
     * @throws Throwable
     */
    public function test_generate_with_a_custom_type_it_should_emit_it_in_the_header()
    {
        $generator = new Generator($this->signer, null, null, 'at+jwt');
        $jwt = $generator->generate(['sub' => 666]);

        $base64Parser = new SafeBase64Parser();
        $header = json_decode($base64Parser->decode(explode('.', $jwt)[0]), true);
        $this->assertSame(['typ' => 'at+jwt', 'alg' => 'HS256'], $header);

        $parser = new Parser($this->signer, null, null, null, ['at+jwt']);
        $this->assertSame(['sub' => 666], $parser->parse($jwt));
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

    public function test_set_and_get_type()
    {
        $generator = new Generator($this->signer, null, null, 'at+jwt');

        $this->assertSame('at+jwt', $generator->getType());
    }

    public function test_get_type_defaults_to_jwt()
    {
        $generator = new Generator($this->signer);

        $this->assertSame('JWT', $generator->getType());
    }
}
