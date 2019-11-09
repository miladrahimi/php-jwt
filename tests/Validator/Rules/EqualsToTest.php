<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use Throwable;

class EqualsToTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_equals_to_the_string()
    {
        $rule = new EqualsTo('text');
        $rule->validate('claim', 'text');

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_equals_to_the_int()
    {
        $rule = new EqualsTo(10);
        $rule->validate('claim', 10);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_equals_to_the_float()
    {
        $rule = new EqualsTo(3.14);
        $rule->validate('claim', 3.14);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_doesnt_equals_to_the_value()
    {
        $rule = new EqualsTo('text');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must equal to `text`.');
        $rule->validate('claim', 'another-text');
    }
}
