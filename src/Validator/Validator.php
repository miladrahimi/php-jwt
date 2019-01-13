<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Class Validator
 *
 * @package MiladRahimi\Jwt\Validator
 */
class Validator implements ValidatorInterface
{
    /**
     * @var array
     */
    protected $rules = [];

    /**
     * @inheritdoc
     */
    public function addRule(string $claimName, Rule $rule)
    {
        $this->rules[$claimName][] = $rule;
    }

    /**
     * @inheritdoc
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
