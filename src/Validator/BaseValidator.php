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
     * @var array
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
     * Clean added rules for given claim
     *
     * @param string $claimName
     */
    public function cleanRules(string $claimName)
    {
        unset($this->rules[$claimName]);
    }

    /**
     * @inheritdoc
     */
    public function validate(array $claims = [])
    {
        /**
         * @var string $claimName
         * @var Rule[] $rules
         */
        foreach ($this->rules as $claimName => $rules) {
            $exists = isset($claims[$claimName]);
            $value = $exists ? $claims[$claimName] : null;

            foreach ($rules as $rule) {
                if ($rule->check($value, $exists) == false) {
                    throw new ValidationException('Validation failed for the claim: ' . $claimName);
                }
            }
        }
    }
}
