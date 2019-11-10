<?php

namespace MiladRahimi\Jwt\Validator\Rules;

use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Validator\Rule;

/**
 * Class GreaterThan
 * It checks if the claim is greater than the given number
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class GreaterThan implements Rule
{
    /**
     * @var float
     */
    protected $number;

    /**
     * @param float $number
     */
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
     *
     * @param string $name
     * @return string
     */
    protected function message(string $name): string
    {
        return "The `$name` must be greater than `$this->number`.";
    }
}
