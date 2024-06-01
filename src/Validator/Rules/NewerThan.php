<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator\Rules;

/**
 * It checks if the claim is newer than the given timestamp
 */
class NewerThan extends GreaterThan
{
    /**
     * @inheritDoc
     */
    protected function message(string $name): string
    {
        return "The `$name` must be newer than `$this->number`.";
    }
}
