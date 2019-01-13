<?php

namespace MiladRahimi\Jwt\Enums;

/**
 * Class PublicClaimNames
 *
 * @package MiladRahimi\Jwt\Enums
 */
class PublicClaimNames
{
    const ISSUER = 'iss';
    const SUBJECT = 'sub';
    const AUDIENCE = 'aud';
    const EXPIRATION_TIME = 'exp';
    const NOT_BEFORE = 'nbf';
    const ISSUED_AT = 'iat';
    const ID = 'jti';
}
