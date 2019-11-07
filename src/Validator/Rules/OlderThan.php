<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class OlderThan
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class OlderThan extends LessThan
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
        return "The `$name` must be older than `$this->number`.";
    }
}
