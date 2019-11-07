<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class NewerThanOrSameTimeWith
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class NewerThanOrSameTimeWith extends GreaterThanOrEqualTo
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
        return "The `$name` must be newer than or equal to `$this->number`.";
    }
}
