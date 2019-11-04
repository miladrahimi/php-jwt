<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rules\Optional\ConsistsOf;
use MiladRahimi\Jwt\Validator\Rules\Optional\EqualsTo;
use MiladRahimi\Jwt\Validator\Rules\Optional\GreaterThan;
use MiladRahimi\Jwt\Validator\Rules\Optional\GreaterThanOrEqualTo;
use MiladRahimi\Jwt\Validator\Rules\Optional\IdenticalTo;
use MiladRahimi\Jwt\Validator\Rules\Optional\LessThan;
use MiladRahimi\Jwt\Validator\Rules\Optional\LessThanOrEqualTo;
use MiladRahimi\Jwt\Validator\Rules\Optional\OlderThan;
use MiladRahimi\Jwt\Validator\Validator;
use MiladRahimi\Jwt\Validator\ValidatorInterface;

class OptionalValidationRulesTest extends TestCase
{
    /**
     * @throws ValidationException
     */
    public function test_consist_of_it_should_pass_when_the_claim_consists_of_the_value()
    {
        $service = $this->service();

        $service->addRule('iss', new ConsistsOf('Company'));

        $service->validate(['iss' => 'My Company']);

        $this->assertTrue(true);
    }

    public function service(): ValidatorInterface
    {
        return new Validator();
    }

    /**
     * @throws ValidationException
     */
    public function test_consist_of_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('iss', new ConsistsOf('Company'));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_consist_of_it_should_fail_when_the_claim_does_not_consists_of_the_value()
    {
        $service = $this->service();

        $service->addRule('iss', new ConsistsOf('Company'));

        $this->expectException(ValidationException::class);

        $service->validate(['iss' => 'My Corporate']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_equals_to_it_should_pass_when_the_claim_equals_to_the_value()
    {
        $service = $this->service();

        $service->addRule('aud', new EqualsTo('Customer'));

        $service->validate(['aud' => 'Customer']);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_equals_to_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('aud', new EqualsTo('Customer'));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_equals_to_it_should_fail_when_the_claim_does_not_equals_to_the_value()
    {
        $service = $this->service();

        $service->addRule('aud', new EqualsTo('Customer'));

        $this->expectException(ValidationException::class);

        $service->validate(['aud' => 'Other Customer']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_greater_than_it_should_pass_when_the_claim_greater_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThan(100));

        $service->validate(['sub' => 200]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_greater_than_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThan(100));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_greater_than_it_should_fail_when_the_claim_is_not_greater_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThan(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => '500']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_greater_than_it_should_fail_when_the_claim_equals_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThan(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => 1000]);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_gt_or_equal_to_it_should_pass_when_the_claim_greater_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThanOrEqualTo(100));

        $service->validate(['sub' => 150]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_gt_or_equal_to_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThanOrEqualTo(100));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_gt_or_equal_to_it_should_fail_when_the_claim_is_not_greater_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThanOrEqualTo(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => '500']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_gt_or_equal_to_it_should_pass_when_the_claim_equals_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new GreaterThanOrEqualTo(1000));

        $service->validate(['sub' => 1000]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_identical_to_it_should_pass_when_the_claim_is_identical_to_int_value()
    {
        $service = $this->service();

        $service->addRule('num', new IdenticalTo(666));

        $service->validate(['num' => 666]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_identical_to_it_should_pass_when_the_claim_is_identical_to_bool_value()
    {
        $service = $this->service();

        $service->addRule('is', new IdenticalTo(true));

        $service->validate(['is' => true]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_identical_to_it_should_fail_when_the_claim_is_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('num', new IdenticalTo(666));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_identical_to_it_should_fail_when_the_claim_is_not_identical_to_int_value()
    {
        $service = $this->service();

        $service->addRule('num', new IdenticalTo(666));

        $this->expectException(ValidationException::class);

        $service->validate(['num' => '666']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_identical_to_it_should_fail_when_the_claim_is_not_identical_to_bool_value()
    {
        $service = $this->service();

        $service->addRule('is', new IdenticalTo(true));

        $this->expectException(ValidationException::class);

        $service->validate(['is' => 1]);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_less_than_it_should_pass_when_the_claim_less_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThan(100));

        $service->validate(['sub' => 90]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_less_than_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThan(100));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_less_than_it_should_fail_when_the_claim_is_not_less_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThan(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => '2000']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_less_than_it_should_fail_when_the_claim_equals_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThan(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => 1000]);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_lt_or_equal_to_it_should_pass_when_the_claim_less_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThanOrEqualTo(100));

        $service->validate(['sub' => 66]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_lt_or_equal_to_it_should_pass_when_the_claim_does_not_exist()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThanOrEqualTo(100));

        $service->validate();

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_lt_or_equal_to_it_should_fail_when_the_claim_is_not_less_than_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThanOrEqualTo(1000));

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => '2000']);

        $this->assertTrue(false);
    }

    /**
     * @throws ValidationException
     */
    public function test_lt_or_equal_to_it_should_pass_when_the_claim_equals_the_value()
    {
        $service = $this->service();

        $service->addRule('sub', new LessThanOrEqualTo(1000));

        $service->validate(['sub' => 1000]);

        $this->assertTrue(true);
    }

    /**
     * @throws ValidationException
     */
    public function test_older_than_it_should_pass_when_the_claim_is_older()
    {
        $service = $this->service();

        $service->addRule('t', new OlderThan(time()));

        $service->validate(['t' => time() - 10000]);

        $this->assertTrue(true);
    }
}
