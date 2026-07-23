<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * Checks whether the claim is older than or the same as the given timestamp.
 */
class OlderThanOrSame extends LessThanOrEqualTo
{
    /**
     * {@inheritDoc}
     */
    protected function message(string $name): string
    {
        return "The `$name` must be older than or the same as `$this->number`.";
    }
}
