<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\ConsistsOf;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;

class EqualsToTest extends TestCase
{
    public function test_validate_it_should_pass_when_claim_equals_to_string()
    {
        $rule = new EqualsTo('text');
        $rule->validate('claim', 'text');

        $this->assertTrue(true);
    }

    public function test_validate_it_should_fail_when_claim_doesnt_equals_to_string()
    {
        $rule = new ConsistsOf('test');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must consist of `mid`.');
        $rule->validate('claim', 'another-text');
    }
}
