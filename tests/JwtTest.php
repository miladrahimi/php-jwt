<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\JwtGenerator;
use MiladRahimi\Jwt\JwtParser;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

class JwtTest extends TestCase
{
    public function test_generate_and_parse_with_sample_claims()
    {
        $generator = new JwtGenerator($this->signer);
        $jwt = $generator->generate($this->sampleClaims);

        $parser = new JwtParser($this->verifier);
        $extractClaims = $parser->parse($jwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    public function test_generate_and_parse_with_validator_it_should_pass_when_rules_are_ok()
    {
        $generator = new JwtGenerator($this->signer);
        $jwt = $generator->generate($this->sampleClaims);

        $validator = new BaseValidator();
        $validator->addRule('sub', new EqualsTo(666));

        $parser = new JwtParser($this->verifier, $validator);
        $extractClaims = $parser->parse($jwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    public function test_generate_and_parse_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $generator = new JwtGenerator($this->signer);
        $jwt = $generator->generate($this->sampleClaims);

        $validator = new BaseValidator();
        $validator->addRule('sub', new EqualsTo(13));

        $parser = new JwtParser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must equal to `13`.');
        $parser->parse($jwt);
    }
}
