<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * The BaseValidator is an implementation of the Validator interface,
 * utilizing predefined rules to validate claims. It is strongly recommended
 * to use or extend this implementation rather than creating your own
 * Validator interface implementation.
 */
class BaseValidator implements Validator
{
    /**
     * @var array[string][int]array
     */
    protected array $rules = [];

    /**
     * Add a new rule
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
                [$rule, $required] = $ruleAndState;

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
