<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class NewerThan
 * It checks if the claim is newer than the given timestamp
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
