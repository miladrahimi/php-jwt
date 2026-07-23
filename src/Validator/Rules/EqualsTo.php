<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Checks whether the claim is equal to the given value.
 */
class EqualsTo implements Rule
{
    /**
     * @var mixed
     */
    private $value;

    /**
     * @param mixed $value
     */
    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * {@inheritDoc}
     */
    public function validate(string $name, $value)
    {
        if ($this->value != $value) {
            $expected = is_scalar($this->value) ? (string)$this->value : gettype($this->value);
            $message = "The `$name` must be equal to `$expected`.";
            throw new ValidationException($message);
        }
    }
}
