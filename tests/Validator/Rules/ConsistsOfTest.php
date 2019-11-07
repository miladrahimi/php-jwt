<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\ConsistsOf;

class ConsistsOfTest extends TestCase
{
    public function test_validate_it_should_pass_when_claim_consists_of_the_substr()
    {
        $rule = new ConsistsOf('sub');
        $rule->validate('claim', 'pre-sub-post');

        $this->assertTrue(true);
    }

    public function test_validate_it_should_fail_when_claim_doesnt_consists_of_the_substr()
    {
        $rule = new ConsistsOf('mid');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must consist of `mid`.');
        $rule->validate('claim', 'pre-sub-post');
    }
}
