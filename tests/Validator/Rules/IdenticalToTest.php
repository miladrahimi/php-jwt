<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\IdenticalTo;
use Throwable;

class IdenticalToTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_is_identical_to_the_string()
    {
        $rule = new IdenticalTo('text');
        $rule->validate('claim', 'text');

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_is_identical_to_the_int()
    {
        $rule = new IdenticalTo(666);
        $rule->validate('claim', 666);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_is_identical_to_the_float()
    {
        $rule = new IdenticalTo(3.14);
        $rule->validate('claim', 3.14);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_is_not_identical_to_the_value()
    {
        $rule = new IdenticalTo('text');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must be identical to `text`.');
        $rule->validate('claim', 'another-text');
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_is_not_identical_to_the_type()
    {
        $rule = new IdenticalTo('3.14');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must be identical to `3.14`.');
        $rule->validate('claim', 3.14);
    }
}
