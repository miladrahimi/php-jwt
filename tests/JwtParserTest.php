<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

class JwtParserTest extends TestCase
{
    public function test_parse_with_sample_jwt()
    {
        $parser = new JwtParser($this->verifier);
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    public function test_validate_with_sample_jwt()
    {
        $parser = new JwtParser($this->verifier);
        $parser->validate($this->sampleJwt);

        $this->assertTrue(true);
    }

    public function test_parse_with_validator_it_should_pass_when_rules_are_ok()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new EqualsTo(666));

        $parser = new JwtParser($this->verifier, $validator);
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    public function test_parse_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new EqualsTo(13));

        $parser = new JwtParser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must equal to `13`.');
        $parser->parse($this->sampleJwt);
    }

    public function test_validate_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new EqualsTo(13));

        $parser = new JwtParser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must equal to `13`.');
        $parser->validate($this->sampleJwt);
    }

    public function test_parse_with_invalid_jwt_it_should_fail()
    {
        $invalidJwt = "abc.xyz";

            $parser = new JwtParser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token format is not valid');
        $parser->parse($invalidJwt);
    }

    public function test_set_and_get_verifier()
    {
        $parser = new JwtParser($this->verifier);

        $this->assertSame($this->verifier, $parser->getVerifier());
    }

    public function test_set_and_get_validator()
    {
        $validator = new BaseValidator();
        $parser = new JwtParser($this->verifier, $validator);

        $this->assertSame($validator, $parser->getValidator());
    }

    public function test_set_and_get_json_parser()
    {
        $jsonParser = new StrictJsonParser();
        $parser = new JwtParser($this->verifier);
        $parser->setJsonParser($jsonParser);

        $this->assertSame($jsonParser, $parser->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $base64Parser = new SafeBase64Parser();
        $parser = new JwtParser($this->verifier);
        $parser->setBase64Parser($base64Parser);

        $this->assertSame($base64Parser, $parser->getBase64Parser());
    }
}
