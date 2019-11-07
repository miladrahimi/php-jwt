<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\JwtParser;

class JwtParserTest extends TestCase
{
    public function test_parse_with_invalid_jwt_it_should_fail()
    {
        $invalidJwt = "abc.xyz";

        $parser = new JwtParser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Token format is not valid');
        $parser->parse($invalidJwt);
    }
}
