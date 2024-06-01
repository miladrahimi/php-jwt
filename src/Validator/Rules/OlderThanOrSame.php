<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * It checks if the claim is older than or same the given timestamp
 */
class OlderThanOrSame extends LessThanOrEqualTo
{
    /**
     * @inheritDoc
     */
    protected function message(string $name): string
    {
        return "The `$name` must be older than or same `$this->number`.";
    }
}
