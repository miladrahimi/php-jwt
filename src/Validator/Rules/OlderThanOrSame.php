<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class OlderThanOrSame
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class OlderThanOrSame extends LessThanOrEqualTo
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
        return "The `$name` must be older than or same `$this->number`.";
    }
}
