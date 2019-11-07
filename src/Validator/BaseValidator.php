<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Class BaseValidator
 *
 * @package MiladRahimi\Jwt\Validator
 */
class BaseValidator implements Validator
{
    /**
     * @var array[string][int]array
     */
    protected $rules = [];

    /**
     * Add a new rule
     *
     * @param string $claimName
     * @param Rule $rule
     * @param bool $required
     */
    public function addRule(string $claimName, Rule $rule, bool $required = true)
    {
        $this->rules[$claimName][] = [$rule, $required];
    }

    /**
     * @inheritdoc
     */
    public function validate(array $claims = [])
    {
        foreach ($this->rules as $claimName => $rules) {
            $exists = isset($claims[$claimName]);
            $value = $exists ? $claims[$claimName] : null;

            foreach ($rules as $ruleAndState) {
                /**
                 * @var Rule $rule
                 * @var bool $required
                 */
                list($rule, $required) = $ruleAndState;

                if ($exists) {
                    $rule->validate($claimName, $value);
                } elseif ($required) {
                    $message = "The `$claimName` is required.";
                    throw  new ValidationException($message);
                }
            }
        }
    }
}
