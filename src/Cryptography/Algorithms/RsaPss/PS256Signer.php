<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss;

class PS256Signer extends AbstractRsaPssSigner
{
    protected static string $name = 'PS256';
}
