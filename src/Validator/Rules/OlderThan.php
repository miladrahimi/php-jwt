<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * It checks if the claim is older than the given timestamp
 */
class OlderThan extends LessThan
{
    /**
     * @inheritDoc
     */
    protected function message(string $name): string
    {
        return "The `$name` must be older than `$this->number`.";
    }
}
