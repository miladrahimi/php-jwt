<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Exceptions\ValidationException;

/**
 * Rule represents a validation logic that will be executed against a JWT claim.
 */
interface Rule
{
    /**
     * Validate the given value
     *
     * @throws ValidationException
     */
    public function validate(string $name, $value);
}
