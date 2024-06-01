<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Enums\PublicClaimNames;
use MiladRahimi\Jwt\Validator\Rules\NewerThan;
use MiladRahimi\Jwt\Validator\Rules\OlderThanOrSame;

/**
 * DefaultValidator is equipped with essential rules right from the start,
 * making it well-suited for general use.
 */
class DefaultValidator extends BaseValidator
{
    public function __construct()
    {
        $this->addOptionalRule(PublicClaimNames::EXPIRATION_TIME, new NewerThan(time()));
        $this->addOptionalRule(PublicClaimNames::NOT_BEFORE, new OlderThanOrSame(time()));
        $this->addOptionalRule(PublicClaimNames::ISSUED_AT, new OlderThanOrSame(time()));
    }
}
