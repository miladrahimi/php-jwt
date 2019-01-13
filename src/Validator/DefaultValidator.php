<?php

namespace MiladRahimi\Jwt\Validator;

use MiladRahimi\Jwt\Enums\PublicClaimNames;
use MiladRahimi\Jwt\Validator\Rules\Optional\NewerThan;
use MiladRahimi\Jwt\Validator\Rules\Optional\OlderThanOrSameTimeWith;

/**
 * Class DefaultValidator
 *
 * @package MiladRahimi\Jwt\Validator
 */
class DefaultValidator extends Validator
{
    /**
     * DefaultVerifier constructor.
     */
    public function __construct()
    {
        $this->addRule(PublicClaimNames::EXPIRATION_TIME, new NewerThan(time()));
        $this->addRule(PublicClaimNames::NOT_BEFORE, new OlderThanOrSameTimeWith(time()));
        $this->addRule(PublicClaimNames::ISSUED_AT, new OlderThanOrSameTimeWith(time()));
    }
}
