<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Enums;

/**
 * Class PublicClaimNames
 *
 * @package MiladRahimi\Jwt\Enums
 */
class PublicClaimNames
{
    public const ISSUER = 'iss';
    public const SUBJECT = 'sub';
    public const AUDIENCE = 'aud';
    public const EXPIRATION_TIME = 'exp';
    public const NOT_BEFORE = 'nbf';
    public const ISSUED_AT = 'iat';
    public const JTI = 'jti';
}
