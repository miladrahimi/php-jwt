<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\NotNull;
use Throwable;

class NotNullTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_is_not_null()
    {
        $rule = new NotNull();
        $rule->validate('claim', 'full');

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_is_empty()
    {
        $rule = new NotNull();

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must not be null.');
        $rule->validate('claim', null);
    }
}
