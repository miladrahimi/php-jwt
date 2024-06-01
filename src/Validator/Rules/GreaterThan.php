<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * It checks if the claim is greater than the given number
 */
class GreaterThan implements Rule
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
        if ($value <= $this->number) {
            throw new ValidationException($this->message($name));
        }
    }

    /**
     * Generate error message
     */
    protected function message(string $name): string
    {
        return "The `$name` must be greater than `$this->number`.";
    }
}
