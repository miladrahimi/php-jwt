<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * It checks if the claim is greater than or equal the given number
 */
class GreaterThanOrEqualTo implements Rule
{
    protected float $number;

    public function __construct(float $number)
    {
        $this->number = $number;
    }

    /**
     * @inheritdoc
     */
    public function validate(string $name, $value)
    {
        if ($value < $this->number) {
            throw new ValidationException($this->message($name));
        }
    }

    /**
     * Generate error message
     */
    protected function message(string $name): string
    {
        return "The `$name` must be greater than or equal to `$this->number`.";
    }
}
