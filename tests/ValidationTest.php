<?php

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rules\Optional\NewerThanOrSameTimeWith;
use MiladRahimi\Jwt\Validator\Rules\Optional\OlderThanOrSameTimeWith;
use MiladRahimi\Jwt\Validator\Rules\Required\Exists;
use MiladRahimi\Jwt\Validator\Rules\Required\NotNull;
use MiladRahimi\Jwt\Validator\Validator;
use MiladRahimi\Jwt\Validator\ValidatorInterface;

class ValidationTest extends TestCase
{
    /**
     * @throws \MiladRahimi\Jwt\Exceptions\ValidationException
     */
    public function test_single_rule_validation_it_should_pass_when_the_rule_is_obeyed()
    {
        $service = $this->service();

        $service->addRule('exp', new Exists());

        $service->validate(['exp' => time()]);

        $this->assertTrue(true);
    }

    public function service(): ValidatorInterface
    {
        return new Validator();
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\ValidationException
     */
    public function test_single_rule_validation_it_should_fail_when_the_rule_is_broken()
    {
        $service = $this->service();

        $service->addRule('exp', new Exists());

        $this->expectException(ValidationException::class);

        $service->validate(['iat' => time()]);

        $this->assertTrue(false);
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\ValidationException
     */
    public function test_validation_with_multiple_rules_it_should_pass_when_all_the_rule_are_obeyed()
    {
        $service = $this->service();

        $service->addRule('nbf', new Exists());
        $service->addRule('nbf', new NewerThanOrSameTimeWith(time()));
        $service->addRule('sub', new NotNull());

        $service->validate(['sub' => 1, 'nbf' => time()]);

        $this->assertTrue(true);
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\ValidationException
     */
    public function test_validation_with_multiple_rules_it_should_fail_when_at_least_one_of_them_is_broken()
    {
        $service = $this->service();

        $service->addRule('nbf', new Exists());
        $service->addRule('nbf', new OlderThanOrSameTimeWith(time()));
        $service->addRule('sub', new NotNull());

        $this->expectException(ValidationException::class);

        $service->validate(['sub' => 1, 'nbf' => time() + 1000]);

        $this->assertTrue(false);
    }

    /**
     * @throws \MiladRahimi\Jwt\Exceptions\ValidationException
     */
    public function test_clean_rules_it_should_clean_rules()
    {
        $service = $this->service();

        $service->addRule('nbf', new Exists());
        $service->addRule('nbf', new OlderThanOrSameTimeWith(time()));
        $service->addRule('sub', new NotNull());

        $service->cleanRules('nbf');

        $service->validate(['sub' => 1]);

        $this->assertTrue(true);
    }
}
