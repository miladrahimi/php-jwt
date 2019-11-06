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
     * @var Rule[][]|array[string][int]Rule
     */
    protected $rules = [];

    /**
     * Add a new rule
     *
     * @param string $claimName
     * @param Rule $rule
     */
    public function addRule(string $claimName, Rule $rule)
    {
        $this->rules[$claimName][] = $rule;
    }

    /**
     * @inheritdoc
     */
    public function validate(array $claims = [])
    {
        foreach ($this->rules as $claimName => $rules) {
            $exists = isset($claims[$claimName]);
            $value = $exists ? $claims[$claimName] : null;

            foreach ($rules as $rule) {
                if ($rule->check($value, $exists) == false) {
                    $message = 'Validation failed for the claim: ' . $claimName;
                    throw new ValidationException($message);
                }
            }
        }
    }
}
