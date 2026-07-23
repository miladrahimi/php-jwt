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
    /**
     * {@inheritDoc}
     *
     * Checks the time-based claims (`exp`, `nbf`, `iat`) against the current time on every call, so long-lived
     * validator instances stay correct.
     */
    public function validate(array $claims)
    {
        $now = time();

        $timeValidator = new BaseValidator();
        $timeValidator->addOptionalRule(PublicClaimNames::EXPIRATION_TIME, new NewerThan($now));
        $timeValidator->addOptionalRule(PublicClaimNames::NOT_BEFORE, new OlderThanOrSame($now));
        $timeValidator->addOptionalRule(PublicClaimNames::ISSUED_AT, new OlderThanOrSame($now));
        $timeValidator->validate($claims);

        parent::validate($claims);
    }
}
