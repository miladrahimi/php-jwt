<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

class JwtParserTest extends TestCase
{
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
}
