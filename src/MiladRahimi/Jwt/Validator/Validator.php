<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 01:27
 */

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

class Validator implements ValidatorInterface
{
    /**
     * @var array
     */
    protected $rules = [];

    /**
     * @inheritdoc
     */
    public function addRule(string $claimName, Rule $rule): void
    {
        $this->rules[$claimName][] = $rule;
    }

    /**
     * @inheritdoc
     */
    public function cleanRules(string $claimName): void
    {
        unset($this->rules[$claimName]);
    }

    /**
     * @inheritdoc
     */
    public function validate(array $claims = []): void
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