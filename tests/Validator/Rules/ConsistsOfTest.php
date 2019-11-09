<?php

namespace MiladRahimi\Jwt\Tests\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\Rules\ConsistsOf;
use Throwable;

class ConsistsOfTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_validate_it_should_pass_when_claim_consists_of_the_substr()
    {
        $rule = new ConsistsOf('sub');
        $rule->validate('claim', 'pre-sub-post');

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_it_should_fail_when_claim_doesnt_consists_of_the_substr()
    {
        $rule = new ConsistsOf('other');

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `claim` must consist of `other`.');
        $rule->validate('claim', 'pre-sub-post');
    }
}
