<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Checks whether the claim is greater than or equal to the given number.
 */
class GreaterThanOrEqualTo implements Rule
{
    protected float $number;

    public function __construct(float $number)
    {
        $this->number = $number;
    }

    /**
     * {@inheritDoc}
     */
    public function validate(string $name, $value)
    {
        if ($value < $this->number) {
            throw new ValidationException($this->message($name));
        }
    }

    /**
     * Builds the validation error message.
     */
    protected function message(string $name): string
    {
        return "The `$name` must be greater than or equal to `$this->number`.";
    }
}
