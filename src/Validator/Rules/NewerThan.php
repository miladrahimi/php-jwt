<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class NewerThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class NewerThan extends GreaterThan
{
    /**
     * @param float $timestamp
     */
    public function __construct(float $timestamp)
    {
        parent::__construct($timestamp);
    }

    /**
     * @inheritDoc
     */
    protected function message(string $name): string
    {
        return "The `$name` must be newer than `$this->number`.";
    }
}
