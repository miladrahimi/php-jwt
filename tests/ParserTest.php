<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Enums\PublicClaimNames;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use Throwable;

class ParserTest extends TestCase
{
    protected Verifier $verifier;

    public function setUp(): void
    {
        parent::setUp();

        $this->verifier = new HS256(new HmacKey('12345678901234567890123456789012'));
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_sample_jwt()
    {
        $parser = new Parser($this->verifier, new BaseValidator());
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_with_sample_jwt()
    {
        $parser = new Parser($this->verifier, new BaseValidator());
        $parser->validate($this->sampleJwt);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_sample_jwt()
    {
        $parser = new Parser($this->verifier);
        $parser->verify($this->sampleJwt);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_validator_it_should_pass_when_rules_are_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule(PublicClaimNames::SUBJECT, new EqualsTo(666));

        $parser = new Parser($this->verifier, $validator);
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule('sub', new EqualsTo(13));

        $parser = new Parser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must equal to `13`.');
        $parser->parse($this->sampleJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule('sub', new EqualsTo(13));

        $parser = new Parser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must equal to `13`.');
        $parser->validate($this->sampleJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_invalid_jwt_it_should_fail()
    {
        $invalidJwt = "abc.xyz";

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT format is not valid');
        $parser->parse($invalidJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_without_typ_it_should_fail()
    {
        $noTypJwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NjYifQ.cIDA-W5EVXB8Y3JQAgPRpIB19fDsaTHPgDg1XoTImA8";

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT header does not have `typ` field.');
        $parser->parse($noTypJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_with_non_jwt_typ()
    {
        $noTypJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IngifQ.eyJzdWIiOiI2NjYifQ.Ut195bqywLi3TtWjo4461lVxo7RudOJGPdD1zBA_Z2gU";

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT of type `x` is not supported.');
        $parser->parse($noTypJwt);
    }

    public function test_set_and_get_verifier()
    {
        $parser = new Parser($this->verifier);

        $this->assertSame($this->verifier, $parser->getVerifier());
    }

    public function test_set_and_get_validator()
    {
        $validator = new BaseValidator();
        $parser = new Parser($this->verifier, $validator);

        $this->assertSame($validator, $parser->getValidator());
    }

    public function test_set_and_get_json_parser()
    {
        $jsonParser = new StrictJsonParser();
        $parser = new Parser($this->verifier, null, $jsonParser);

        $this->assertSame($jsonParser, $parser->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $base64Parser = new SafeBase64Parser();
        $parser = new Parser($this->verifier, null, null, $base64Parser);

        $this->assertSame($base64Parser, $parser->getBase64Parser());
    }
}
