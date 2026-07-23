<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Checks whether the claim is newer than or the same as the given timestamp.
 */
class NewerThanOrSame extends GreaterThanOrEqualTo
{
    /**
     * {@inheritDoc}
     */
    protected function message(string $name): string
    {
        return "The `$name` must be newer than or the same as `$this->number`.";
    }
}
