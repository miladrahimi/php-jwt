<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\GreaterThanOrEqualTo;
use Throwable;

class GreaterThanOrEqualToTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_is_greater_than_the_value()
    {
        $rule = new GreaterThanOrEqualTo(13);
        $rule->validate('claim', 666);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_equals_to_the_value()
    {
        $rule = new GreaterThanOrEqualTo(666);
        $rule->validate('claim', 666);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_is_less_than_the_value()
    {
        $rule = new GreaterThanOrEqualTo(666);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must be greater than or equal to `666`.');
        $rule->validate('claim', 13);
    }
}
