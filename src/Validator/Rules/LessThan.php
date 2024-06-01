<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * It checks if the claim is less than the given number
 */
class LessThan implements Rule
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
        if ($value >= $this->number) {
            throw new ValidationException($this->message($name));
        }
    }

    /**
     * Generate error message
     */
    protected function message(string $name): string
    {
        return "The `$name` must be less than `$this->number`.";
    }
}
