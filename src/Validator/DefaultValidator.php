<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Enums\PublicClaimNames;
use MiladRahimi\Jwt\Validator\Rules\NewerThan;
use MiladRahimi\Jwt\Validator\Rules\OlderThanOrSameTimeWith;

/**
 * Class DefaultValidator
 *
 * @package MiladRahimi\Jwt\Validator
 */
class DefaultValidator extends BaseValidator
{
    /**
     * DefaultVerifier constructor.
     */
    public function __construct()
    {
        $this->addRule(
            PublicClaimNames::EXPIRATION_TIME,
            new NewerThan(time()),
            false
        );
        $this->addRule(
            PublicClaimNames::NOT_BEFORE,
            new OlderThanOrSameTimeWith(time()),
            false
        );
        $this->addRule(
            PublicClaimNames::ISSUED_AT,
            new OlderThanOrSameTimeWith(time()),
            false
        );
    }
}
