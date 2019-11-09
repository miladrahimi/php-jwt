<?php

namespace MiladRahimi\Jwt\Tests\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Tests\TestCase;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\ConsistsOf;
use MiladRahimi\Jwt\Validator\Rules\IdenticalTo;
use Throwable;

class BaseValidatorTest extends TestCase
{
    /**
     * @throws Throwable
     */
    public function test_with_valid_rule_it_should_pass()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'));
        $validator->validate([
            'sub' => 'TheValue',
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_some_valid_rules_for_one_claim_it_should_pass()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'));
        $validator->addRule('sub', new ConsistsOf('Value'));
        $validator->validate([
            'sub' => 'TheValue',
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_some_valid_rules_for_different_claims_it_should_pass()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'));
        $validator->addRule('jti', new IdenticalTo('TheID'));
        $validator->validate([
            'sub' => 'TheValue',
            'jti' => 'TheID',
        ]);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_with_invalid_rule_it_should_fail()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'));

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must be identical to `TheValue`.');
        $validator->validate([
            'sub' => 'AnotherValue',
        ]);
    }

    /**
     * @throws Throwable
     */
    public function test_with_required_rule_it_should_fail_when_claim_not_present()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'));

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` is required.');
        $validator->validate([]);
    }

    /**
     * @throws Throwable
     */
    public function test_with_optional_rule_it_should_pass_when_claim_not_present()
    {
        $validator = new BaseValidator();
        $validator->addRule('sub', new IdenticalTo('TheValue'), false);
        $validator->validate([]);

        $this->assertTrue(true);
    }
}
