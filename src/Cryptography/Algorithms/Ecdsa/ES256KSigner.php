<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

class ES256KSigner extends AbstractEcdsaSigner
{
    protected static string $name = 'ES256K';
}
