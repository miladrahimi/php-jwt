<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * It checks if the claim is newer than or same the given timestamp
 */
class NewerThanOrSame extends GreaterThanOrEqualTo
{
    /**
     * @inheritDoc
     */
    protected function message(string $name): string
    {
        return "The `$name` must be newer than or same `$this->number`.";
    }
}
