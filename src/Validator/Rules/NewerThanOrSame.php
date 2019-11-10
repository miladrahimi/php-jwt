<?php

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Class NewerThanOrSame
 * It checks if the claim is newer than or same the given timestamp
 *
 * @package MiladRahimi\Jwt\Validator\Rules
 */
class NewerThanOrSame extends GreaterThanOrEqualTo
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
        return "The `$name` must be newer than or same `$this->number`.";
    }
}
